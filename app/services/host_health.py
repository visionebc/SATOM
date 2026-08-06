"""Health of the MACHINE the manager runs on — the sixth scope, and the only
one that could not deliver bad news before 2026-08-06.

``system_health.host_stats()`` has reported CPU load, memory and filesystem
usage for both nodes since the Monitoring page was written. Nothing ever
**graded** it. The numbers were printed on a card and no threshold, no roll-up
and no alert existed anywhere in the product:

    grep -rn "disk\\|load\\|mem" app/services/infra_health.py  ->  0 grading

The consequence is on record. On 2026-07-28 satom-node-1 filled to **95 %**
disk in six minutes (a load generator writing 7.9 GB of curl bodies to a log).
Every unit stayed active, ``/healthz`` stayed 200, the badge stayed green and
the mailbox stayed empty. It was found by a human looking at ``df``. At the
target fleet size that recurs and there is still no signal.

This module supplies the missing grade. Three rules it keeps, all of them
learned the hard way elsewhere in this codebase:

**A node we could not read is ``unknown``, never ``ok``.** A standby whose
``/healthz`` did not answer has told us nothing about its disk. Reporting that
as healthy is the exact defect that made the Fleet health badge structurally
incapable of turning red (see :mod:`app.services.device_health`).

**Both nodes are graded, from one place.** The peer's numbers already ride its
``/healthz`` response, so the standby is covered without SSH and without a
second implementation. A primary-only disk check would have missed the node
that is *more* likely to fill up: the standby holds the replicated ``data/``
tree and the WAL.

**A filesystem that appears twice is graded once.** ``host_stats`` already
de-duplicates by total size (``/``, ``/opt/satom`` and ``/var/log`` are one
device on every node in this fleet), so three mounts of one filesystem cannot
produce three alerts about the same disk.

Thresholds come from the ``host`` scope of :mod:`app.services.thresholds`, so
they are declared in one form rather than argued about in a literal.
"""
from __future__ import annotations

from . import thresholds as th

RANK = {"unknown": 0, "ok": 1, "warn": 2, "crit": 3}

SIGNAL_LABEL = {"disk": "Filesystem", "memory": "Memory", "load": "CPU load"}


def worst_of(statuses) -> str:
    out = "unknown"
    for s in statuses:
        if RANK.get(s, 0) > RANK.get(out, 0):
            out = s
    return out


def _grade(value, warn, crit) -> str:
    """``crit``/``warn``/``ok`` for a value where HIGHER is worse.

    A level of 0 is off, matching every other threshold in the product. A
    ``None`` value is ``unknown`` — the reading is missing, not fine.
    """
    if value is None:
        return "unknown"
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "unknown"
    if crit and v >= float(crit):
        return "crit"
    if warn and v >= float(warn):
        return "warn"
    return "ok"


def limits() -> dict:
    """The six host thresholds, resolved once per grading pass."""
    return {k: th.host(k).value for k in
            ("disk_warn_pct", "disk_crit_pct", "mem_warn_pct", "mem_crit_pct",
             "load_warn_pct", "load_crit_pct")}


def grade_stats(stats: dict | None, lim: dict | None = None) -> dict:
    """Grade one node's ``host_stats`` payload. Pure: no I/O, no ORM.

    Returns ``{status, signals: {...}, reasons: [...]}`` in the same shape the
    device roll-up uses, so the page and the alert engine can render both with
    one template and one severity ladder.
    """
    lim = lim or limits()
    if not stats:
        sig = {k: {"status": "unknown", "text": "no reading from this node"}
               for k in ("disk", "memory", "load")}
        return {"status": "unknown", "signals": sig,
                "reasons": [{"signal": "disk", "label": SIGNAL_LABEL["disk"],
                             **sig["disk"]}], "stats": None}

    signals: dict[str, dict] = {}

    # --- filesystems ---------------------------------------------------
    disks = stats.get("disks") or []
    if not disks:
        signals["disk"] = {"status": "unknown", "text": "no filesystem reading"}
    else:
        rows = []
        for d in disks:
            st = _grade(d.get("pct"), lim["disk_warn_pct"], lim["disk_crit_pct"])
            rows.append((st, d))
        st = worst_of([r[0] for r in rows])
        bad = [d for s, d in rows if s in ("warn", "crit")]
        if bad:
            text = "; ".join(
                "%s %.0f%% used (%.0f of %.0f GB, budget %g%%)"
                % (d.get("mount") or "?", d.get("pct") or 0,
                   d.get("used_gb") or 0, d.get("total_gb") or 0,
                   lim["disk_warn_pct"])
                for d in bad[:3])
        else:
            worst_pct = max((d.get("pct") or 0) for d in disks)
            text = "%d filesystem%s, worst %.0f%% used" % (
                len(disks), "s" if len(disks) != 1 else "", worst_pct)
        signals["disk"] = {"status": st, "text": text,
                           "rows": [dict(d, status=s) for s, d in rows]}

    # --- memory ---------------------------------------------------------
    mp = stats.get("mem_pct")
    st = _grade(mp, lim["mem_warn_pct"], lim["mem_crit_pct"])
    if mp is None:
        signals["memory"] = {"status": "unknown", "text": "no memory reading"}
    else:
        signals["memory"] = {
            "status": st,
            "text": "%.0f%% used (%s of %s MB, budget %g%%)" % (
                mp, stats.get("mem_used_mb"), stats.get("mem_total_mb"),
                lim["mem_warn_pct"])
            if st != "ok" else "%.0f%% used" % mp,
            "pct": mp}

    # --- load ------------------------------------------------------------
    # Reported as a PERCENTAGE OF CORES, not as a raw load average: "load 6" is
    # a crisis on 2 cores and idle on 32, so a fleet-wide threshold has to be
    # normalised or it means something different on every node.
    lp = stats.get("load_pct")
    st = _grade(lp, lim["load_warn_pct"], lim["load_crit_pct"])
    if lp is None:
        signals["load"] = {"status": "unknown", "text": "no load reading"}
    else:
        load = stats.get("load") or []
        signals["load"] = {
            "status": st,
            "text": "%.0f%% of %s core%s (load %s, budget %g%%)" % (
                lp, stats.get("cpus"), "s" if (stats.get("cpus") or 0) != 1 else "",
                "/".join("%g" % v for v in load) or "?", lim["load_warn_pct"])
            if st != "ok" else "%.0f%% of %s cores" % (lp, stats.get("cpus")),
            "pct": lp}

    status = worst_of([s["status"] for s in signals.values()])
    reasons = [{"signal": k, "label": SIGNAL_LABEL[k], **v}
               for k, v in signals.items() if v["status"] != "ok"]
    reasons.sort(key=lambda r: -RANK.get(r["status"], 0))
    return {"status": status, "signals": signals, "reasons": reasons,
            "stats": stats}


def grade_node(node: dict, lim: dict | None = None) -> dict:
    """Grade one entry of :func:`app.services.infra_health.nodes`.

    An unreachable node is graded ``unknown`` with the reason stated, not
    skipped: a node we cannot read is a gap in coverage and it has to appear as
    one. Whether the node being unreachable is itself an alert belongs to the
    redundancy check, which already owns that question — duplicating it here
    would send two mails for one dead standby.
    """
    lim = lim or limits()
    out = {"name": node.get("name") or "?", "host": node.get("host") or "",
           "is_local": bool(node.get("is_local")),
           "role": node.get("role"),
           "reachable": bool(node.get("reachable"))}
    if not out["reachable"]:
        out.update(status="unknown", signals={}, reasons=[
            {"signal": "disk", "label": "Node",
             "status": "unknown",
             "text": "node unreachable — its disk, memory and load are unknown"}],
            stats=None)
        return out
    out.update(grade_stats(node.get("host_stats"), lim))
    return out


def local() -> dict:
    """Grade THIS node only. No network, so a page may call it directly."""
    from . import system_health as shealth
    lim = limits()
    try:
        stats = shealth.host_stats()
    except Exception:  # noqa: BLE001 — a broken probe must not sink the page
        stats = None
    g = grade_stats(stats, lim)
    g.update(name=(stats or {}).get("hostname") or "this node",
             is_local=True, reachable=True)
    return g


def fleet(nodes=None) -> dict:
    """Grade every registered node. ``nodes`` may be supplied by a caller that
    already has the infra payload, so the page does not probe the peer twice."""
    lim = limits()
    if nodes is None:
        try:
            from . import infra_health
            nodes = infra_health.nodes()
        except Exception:  # noqa: BLE001
            nodes = []
    graded = [grade_node(n, lim) for n in (nodes or [])]
    if not graded:
        graded = [local()]
    return {"nodes": graded,
            "status": worst_of([n["status"] for n in graded]),
            "limits": lim}
