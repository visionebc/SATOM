"""System Automations arm themselves — the first device a node gets seeds them.

System Automations are SATOM keeping its own data current: the source-of-truth
syncs, the nightly system backup, the probe and metrics sweeps, the Sentinel
jobs, the feed refreshes. Until 2026-10-14 nothing created them except the
operator running ``satom execute seed actions --yes``
(deploy/satom_cli/cmd_fix.py), whose own docstring names the consequence: a
brand-new node has every capability and zero coverage, and looks perfectly
healthy while it takes no backups at all.

Operator rule (2026-10-14): they are created by themselves when devices are
added. :func:`ensure_seeded` is called from the one seam every
appliance-creation path already reaches (``monitoring_provision.
provision_monitoring``, held there by an AST guard), so the first device that
lands on a node arms the default set.

ONLY FROM ZERO. Rows are data and operator edits win over code defaults in this
product, so the seed fires only while the node has NO system automation at
all. A node that has even one keeps exactly what its administrator left —
deleting the weekly report is a choice, and re-creating it on the next device
add would overrule it. The CLI command still fills individual gaps on demand.

The plan below is the CLI's ``SEED_PLAN``, the same rows in the same order;
tests/test_system_automations_seed.py fails the day the two disagree. It is
kept here rather than imported from ``deploy/`` because ``deploy/`` is the
signed root-executed tree, which the application does not import from.
"""
from __future__ import annotations

import json

from ..errors import log_exception

#: Created by the seed, so the list page and the audit trail say who made them.
SEED_AUTHOR = "system:auto-seed"

#: (action, name, schedule_kind, schedule, params, product) — identical to
#: deploy/satom_cli/cmd_fix.py SEED_PLAN (see the module docstring).
SEED_PLAN = [
    ("device_sync", "Hourly fleet sync (source of truth)", "interval",
     {"every": 60, "unit": "minutes"}, {}, "fortiweb"),
    ("device_inspect", "Nightly SoT snapshot + off-box push (all devices)", "daily",
     {"time": "02:45"}, {}, "fortiweb"),
    ("system_backup", "Nightly system backup (Postgres + JSON -> server)", "daily",
     {"time": "01:30"}, {"push_server": True}, "fortiweb"),
    ("deep_monitor", "Deep monitors + Service Monitor — probe sweep", "interval",
     {"every": 3, "unit": "minutes"}, {}, "global"),
    ("metrics_scrape", "Fleet metrics — scrape to the local store", "interval",
     {"every": 3, "unit": "minutes"}, {}, "global"),
    ("inventory_snapshot", "Daily inventory snapshot (Metrics trend)", "daily",
     {"time": "23:50"}, {}, "global"),
    ("monitor_report", "Daily monitoring report", "daily",
     {"time": "02:00"}, {"period": "daily", "email": True, "push_server": True, "keep": 90}, "global"),
    ("monitor_report", "Weekly monitoring report", "weekly",
     {"weekday": 0, "time": "02:10"},
     {"period": "weekly", "email": True, "push_server": True, "keep": 53}, "global"),
    ("monitor_report", "Monthly monitoring report", "monthly",
     {"day": 1, "time": "02:20"},
     {"period": "monthly", "email": True, "push_server": True, "keep": 36}, "global"),
    ("sentinel_sweep", "Sentinel — correlate and score", "interval",
     {"every": 3, "unit": "minutes"}, {}, "global"),
    ("sentinel_baseline", "Sentinel — recompute behavioural baselines", "daily",
     {"time": "03:10"}, {}, "global"),
    ("sentinel_vuln_sync", "Sentinel — refresh the local CVE mirror", "daily",
     {"time": "03:30"}, {}, "global"),
    ("knowledge_fetch", "Knowledge packs — check the feed, download, import", "daily",
     {"time": "04:20"}, {}, "global"),
    ("signature_check", "Signature DB freshness — read each FortiWeb's version", "daily",
     {"time": "06:15"}, {}, "fortiweb"),
]


def is_system_row(row) -> bool:
    """True for a row the System Automations page owns.

    The same partition as views.scheduled_actions.effective_scope: only the
    catalog's literal 'user' is an operator automation; everything else,
    including a key the catalog no longer has, is the system's.
    """
    from . import scheduled_actions as sa
    spec = sa.get_spec(row.action)
    raw = spec.scope if spec is not None else (row.scope or "")
    return raw != "user"


def ensure_seeded(*, session=None) -> dict:
    """Create :data:`SEED_PLAN` if the node has no system automation at all.

    Returns ``{"created": [name, ...]}``, or ``{"created": [], "skipped": why}``.
    Never raises: a failed seed must not cost the operator the device row the
    caller just saved. It is reported instead (``errors``).
    """
    from ..models import ScheduledAction, db
    from . import scheduled_actions as sa
    from .scheduler import compute_next_run

    session = session or db.session
    out: dict = {"created": [], "errors": []}
    try:
        if any(is_system_row(r) for r in session.query(ScheduledAction).all()):
            out["skipped"] = "system automations already present"
            return out
        tz = sa._configured_tz()
        for key, name, kind, sched, params, product in SEED_PLAN:
            if sa.get_spec(key) is None:
                # A plan entry the catalog dropped would seed an orphan that
                # fires as "Unknown action" every cycle. Skip it, loudly.
                out["errors"].append("%s: not in the action catalog" % key)
                continue
            row = ScheduledAction(
                name=name, scope="admin", product=product, action=key,
                targets="[]", params=json.dumps(params), schedule_kind=kind,
                schedule=json.dumps(sched), enabled=True, catch_up=True,
                created_by=SEED_AUTHOR)
            row.next_run = compute_next_run(kind, sched, tz=tz)
            session.add(row)
            out["created"].append(name)
        session.commit()
    except Exception as exc:                     # noqa: BLE001
        session.rollback()
        log_exception(exc, context="system_automations.ensure_seeded")
        out["created"] = []
        out["errors"].append("system automations: %s" % str(exc)[:120])
    return out


__all__ = ["SEED_AUTHOR", "SEED_PLAN", "ensure_seeded", "is_system_row"]
