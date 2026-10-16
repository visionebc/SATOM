# app/services/observatory.py
"""HTTP Observatory — run, store and read scans of published sites.

The pieces: :mod:`header_observatory` grades, :mod:`observatory_scan` fetches,
:mod:`observatory_fix` attributes and fixes. This module is what the page,
the ``observatory_scan`` scheduled action and the re-scan after a fix share:
one place that turns a scan into a stored row, so the three can never disagree
about what was kept.
"""
from __future__ import annotations

import json
from datetime import datetime

from ..models import db
from ..models_observatory import ObservatoryScan
from . import observatory_scan as osc

#: Rows kept per site (appliance + policy). Older ones are pruned on insert.
KEEP_PER_SITE = 60


def _store(appliance, result: dict, trigger: str, username: str) -> ObservatoryScan:
    analysis = result.get("analysis") or {}
    row = ObservatoryScan(
        appliance_id=appliance.id, product=appliance.kind,
        policy=(result.get("target") or {}).get("policy") or "",
        host=result.get("host") or "",
        started_at=datetime.utcfromtimestamp(result.get("started") or 0) if result.get("started")
        else datetime.utcnow(),
        finished_at=datetime.utcfromtimestamp(result["finished"]) if result.get("finished") else None,
        grade=result.get("grade"), score=result.get("score"),
        tests_passed=analysis.get("tests_passed"), tests_failed=analysis.get("tests_failed"),
        error=result.get("error") or "",
        result=json.dumps({"target": result.get("target"),
                           "analysis": analysis or None,
                           "retrieval": result.get("retrieval")}),
        trigger=trigger if trigger in ObservatoryScan.TRIGGERS else "manual",
        username=(username or "")[:64])
    db.session.add(row)
    db.session.commit()
    _prune(appliance.id, row.policy)
    return row


def _prune(appliance_id: int, policy: str) -> None:
    old = (ObservatoryScan.query
           .filter_by(appliance_id=appliance_id, policy=policy)
           .order_by(ObservatoryScan.started_at.desc(), ObservatoryScan.id.desc())
           .offset(KEEP_PER_SITE).all())
    if old:
        for r in old:
            db.session.delete(r)
        db.session.commit()


def run(appliance, target: osc.Target, host: str | None = None, *,
        trigger: str = "manual", username: str = "") -> ObservatoryScan:
    """Scan one site and store the row (graded or not)."""
    return _store(appliance, osc.scan(target, host), trigger, username)


def previous(row: ObservatoryScan) -> ObservatoryScan | None:
    """The graded scan of the same site before *row*."""
    return (ObservatoryScan.query
            .filter(ObservatoryScan.appliance_id == row.appliance_id,
                    ObservatoryScan.policy == row.policy,
                    ObservatoryScan.id != row.id,
                    ObservatoryScan.started_at <= row.started_at,
                    ObservatoryScan.grade.isnot(None))
            .order_by(ObservatoryScan.started_at.desc(), ObservatoryScan.id.desc())
            .first())


def latest_by_policy(appliance_id: int) -> dict[str, ObservatoryScan]:
    """Newest row per policy of one appliance."""
    out: dict[str, ObservatoryScan] = {}
    rows = (ObservatoryScan.query.filter_by(appliance_id=appliance_id)
            .order_by(ObservatoryScan.started_at.desc(), ObservatoryScan.id.desc())
            .limit(2000).all())
    for r in rows:
        out.setdefault(r.policy, r)
    return out


def history(appliance_id: int, policy: str, limit: int = KEEP_PER_SITE) -> list[ObservatoryScan]:
    return (ObservatoryScan.query.filter_by(appliance_id=appliance_id, policy=policy)
            .order_by(ObservatoryScan.started_at.desc(), ObservatoryScan.id.desc())
            .limit(limit).all())


def _rank(grade: str | None) -> int:
    from .header_observatory import GRADES
    return GRADES.index(grade) if grade in GRADES else len(GRADES)


def scan_appliance(appliance, *, trigger: str = "scheduled", username: str = "system",
                   dry_run: bool = False) -> dict:
    """Every scannable site of one appliance — the scheduled action's body.

    Returns ``{ok, summary, log}`` like every scheduled executor. A site that
    cannot be graded is a named line in the log, not a failure of the run; a
    device whose sites cannot be listed IS a failure (unknown is not "no
    sites"). A grade lower than the previous run is called out first.
    """
    try:
        targets = osc.targets_for(appliance)
    except Exception as exc:  # noqa: BLE001 — unreadable box = failed run
        return {"ok": False, "summary": "%s: could not list published sites: %s"
                % (appliance.name, exc), "log": ""}
    scannable = [t for t in targets if t.scannable]
    if dry_run:
        return {"ok": True, "summary": "%s: would grade %d of %d sites."
                % (appliance.name, len(scannable), len(targets)),
                "log": "\n".join("%s %s" % (t.policy, "" if t.scannable else "(skipped: %s)" % t.note)
                                 for t in targets)}
    lines, dropped, graded = [], [], 0
    for t in targets:
        if not t.scannable:
            lines.append("%s: skipped — %s" % (t.policy, t.note or "not scannable"))
            continue
        row = run(appliance, t, trigger=trigger, username=username)
        if row.grade:
            graded += 1
            prev = previous(row)
            drop = prev is not None and _rank(row.grade) > _rank(prev.grade)
            if drop:
                dropped.append("%s %s→%s" % (t.policy, prev.grade, row.grade))
            lines.append("%s: %s (%d)%s" % (t.policy, row.grade, row.score or 0,
                                            "  DROPPED from %s" % prev.grade if drop else ""))
        else:
            lines.append("%s: not graded — %s" % (t.policy, row.error))
    summary = "%s: %d of %d sites graded." % (appliance.name, graded, len(scannable))
    if dropped:
        summary = "Grade dropped: %s. " % ", ".join(dropped) + summary
    return {"ok": True, "summary": summary, "log": "\n".join(lines)}
