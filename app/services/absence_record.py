"""The ledger of corroborated disappearances — write, read, review.

:mod:`app.services.absence_corroboration` owns the RULE and touches no
database; this module owns the RECORD. Split on purpose: the rule is the part
other subsystems (upgrades, provisioning, templates) will reuse, and a rule
that imports ``db`` cannot be unit-tested without an app context.

What gets recorded
------------------
Only rows the comparison already classified as *gone* — base scope serves the
path, target scope rejects it. Everything else on that page is a gap in the
evidence and recording it would put unasked questions in a table whose whole
purpose is to hold answers.

Re-proving an absence UPDATES its row (``seen_count`` / ``last_seen_at``). A
new row per evaluation would make "since when?" unanswerable, which is the one
question a lifecycle ledger exists to answer.

Auto-correction, and the part of it that is blocked
---------------------------------------------------
Two things were asked for: that the system correct itself, and that the
correction be reviewable. One of them is implementable today and the other is
not, and the difference is structural rather than a matter of effort:

* **Implemented.** A ``confirmed`` finding is ACKNOWLEDGED automatically (see
  :data:`K_AUTOACK`, default on). The comparison keeps reporting it — it is a
  true finding about the firmware — but it stops being an *open question*:
  the ledger holds the proof, its date and both sources, the alert engine goes
  quiet about it, and the review queue shows only what still needs a human.
  That is the system reviewing its own output, and it is auditable.

* **Blocked, deliberately.** Rewriting the endpoint catalog for a
  ``contradicted`` finding cannot be done correctly: ``RegistryEndpoint`` is
  keyed ``(product, api_version, name)`` with **one URN per name and no
  firmware dimension**, and a contradicted row is by construction one whose
  BASE scope still serves the current URN. Writing the target line's spelling
  would therefore break the base line every single time. ``cli_coverage``
  rule 3 independently forbids picking between two spellings from a config
  file. So the candidate path is recorded and alerted, and the write is
  refused with :data:`BLOCKED_REASON` rather than attempted — a correction
  that breaks the other half of the fleet is not a correction.

  What unblocks it is a per-line dimension on the catalog, which is a change
  to the resolution path every service in the product goes through. That is a
  round of its own, not a side effect of this one.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from ..extensions import db
from ..models import AppSetting
from ..models_lifecycle import (CORR_APPLIED, CORR_DISMISSED, CORR_NONE,
                                CORR_PROPOSED, ObjectAbsence)
from . import absence_corroboration as corr
from . import api_matrix, cli_coverage

#: Setting key: acknowledge a corroborated absence without asking. Default on —
#: an operator who has to click "yes, 8.0 removed this" once per firmware line
#: per object is being asked to confirm a measurement, not to make a decision.
K_AUTOACK = "absence.autoack"
#: Setting key: master switch for writing the ledger at all.
K_ENABLED = "absence.record"

BLOCKED_REASON = (
    "Not written: the endpoint catalog holds ONE URN per name with no firmware "
    "dimension, and this finding's base scope is still served by the current "
    "URN — writing the other spelling would break it. Verify the path in the "
    "console and decide per line."
)


def _flag(key: str, default: bool = True) -> bool:
    raw = AppSetting.get(key)
    if raw is None:
        return default
    return str(raw).strip() not in ("0", "false", "False", "")


def _version_key(scope: str) -> tuple:
    """Sort key for a firmware line/build. Non-numeric parts sort last.

    ``"8.0"`` must come after ``"7.6"`` and ``"10.0"`` after ``"8.0"`` — a
    string sort gets the second one wrong, and a line ordering that is wrong is
    a pair ordering that is wrong, which inverts every added/removed verdict
    downstream.
    """
    parts = []
    for chunk in (scope or "").split("."):
        try:
            parts.append((0, int(chunk)))
        except ValueError:
            parts.append((1, chunk))
    return tuple(parts)


def line_pairs(product: str, matrix: dict | None = None) -> list[tuple]:
    """Adjacent ``(older, newer)`` line pairs for a product.

    ADJACENT, not every combination: 7.6 -> 8.0 -> 8.2 asks two questions and
    the cross pair 7.6 -> 8.2 asks a third that is already answered by the
    other two and would double-count every object removed in 8.0. Lines rather
    than builds, because a ledger keyed on builds grows a row per patch release
    for a fact that is true of the line.
    """
    matrix = matrix if matrix is not None else (api_matrix.load(product) or {})
    lines = sorted((matrix.get("lines") or {}).keys(), key=_version_key)
    return list(zip(lines, lines[1:]))


def _evaluate_pair(product: str, base: str, target: str) -> list[dict]:
    """Corroborated verdicts for one line pair. Pure read, no DB writes."""
    delta = api_matrix.diff(product, base, target)
    removed = delta.get("endpoints_removed") or []
    if not removed:
        return []
    base_prov = cli_coverage.provenance(product, line=base)
    target_prov = cli_coverage.provenance(product, line=target)
    out = []
    for row in removed:
        name = row.get("endpoint") or ""
        rec_b = base_prov.for_name(name) if base_prov else None
        rec_t = target_prov.for_name(name) if target_prov else None
        state = corr.corroborate(second_now=corr.source_of(rec_t),
                                 second_before=corr.source_of(rec_b))
        out.append({
            "product": product, "name": name, "urn": row.get("urn") or "",
            "base_scope": base, "target_scope": target, "state": state,
            "cli_base": (rec_b or {}).get("bucket") or corr.SRC_SILENT,
            "cli_target": (rec_t or {}).get("bucket") or corr.SRC_SILENT,
            "cli_device": target_prov.device if target_prov else "",
            "cli_captured_at": target_prov.captured_at if target_prov else "",
            "proposed_path": corr.proposed_path(rec_t),
            "api_detail": "; ".join(
                str(x) for x in (row.get("attested_on") or [])) or "",
        })
    return out


def evaluate(product: str) -> list[dict]:
    """Every corroborated verdict for a product, across adjacent line pairs."""
    findings = []
    for base, target in line_pairs(product):
        try:
            findings.extend(_evaluate_pair(product, base, target))
        except Exception:  # noqa: BLE001 — one unreadable pair never sinks the rest
            continue
    return findings


def record(product: str) -> dict:
    """Evaluate and persist. ``{evaluated, created, updated, persisted}``.

    ``persisted`` is False on a read-only standby (the commit raises and is
    rolled back) and the computed findings are still returned, so a caller on
    the replica can render and alert on truth it merely cannot store. Reporting
    a write that did not happen is how a backup log earns a false ``[OK]``.
    """
    findings = evaluate(product)
    summary = {"product": product, "evaluated": len(findings),
               "created": 0, "updated": 0, "persisted": False,
               "findings": findings}
    if not _flag(K_ENABLED):
        summary["skipped"] = "disabled (%s)" % K_ENABLED
        return summary
    autoack = _flag(K_AUTOACK)
    now = datetime.utcnow()
    try:
        for f in findings:
            row = ObjectAbsence.query.filter_by(
                product=f["product"], name=f["name"],
                base_scope=f["base_scope"],
                target_scope=f["target_scope"]).first()
            if row is None:
                row = ObjectAbsence(first_seen_at=now, seen_count=0,
                                    **{k: f[k] for k in (
                                        "product", "name", "base_scope",
                                        "target_scope")})
                db.session.add(row)
                summary["created"] += 1
            else:
                summary["updated"] += 1
            # Evidence is refreshed on every pass: a dump captured yesterday
            # can change the verdict, and a row that kept its first answer
            # would be a ledger of what we used to believe.
            row.urn = f["urn"]
            row.state = f["state"]
            row.cli_base = f["cli_base"]
            row.cli_target = f["cli_target"]
            row.cli_device = f["cli_device"]
            row.cli_captured_at = f["cli_captured_at"]
            row.api_detail = f["api_detail"]
            row.proposed_path = f["proposed_path"]
            row.last_seen_at = now
            row.seen_count = (row.seen_count or 0) + 1
            # A human decision is never overwritten by the timer. Only rows
            # nobody has touched get the automatic treatment, and only the
            # corroborated state earns it: a contradiction is precisely the
            # case that needs the human this would be replacing.
            # ``or CORR_NONE`` is not defensive noise. A row created in this
            # loop has ``correction is None`` in Python -- the column default
            # is applied by the INSERT, which has not happened yet -- so the
            # bare membership test was False for exactly the rows this branch
            # exists to treat, and every brand-new corroborated finding stayed
            # unacknowledged while the code read as though it handled them.
            if (row.correction or CORR_NONE) in (CORR_NONE, CORR_PROPOSED):
                if f["state"] == corr.STATE_CONTRADICTED and f["proposed_path"]:
                    row.correction = CORR_PROPOSED
                elif f["state"] == corr.STATE_CONFIRMED and autoack:
                    row.correction = CORR_APPLIED
                    row.correction_note = (
                        "Acknowledged automatically: two sources agree. "
                        "No catalog write — the finding is about the firmware, "
                        "not about the catalog entry.")
                    row.reviewed_by = "system"
                    row.reviewed_at = now
                else:
                    row.correction = CORR_NONE
        db.session.commit()
        summary["persisted"] = True
    except Exception as exc:  # noqa: BLE001
        db.session.rollback()
        summary["error"] = str(exc)
    return summary


# ---------------------------------------------------------------------------
# read side
# ---------------------------------------------------------------------------
def open_findings(product: str = "") -> list:
    """Rows still waiting for a human, newest first."""
    q = ObjectAbsence.query.filter(
        ObjectAbsence.correction.in_((CORR_NONE, CORR_PROPOSED)))
    if product:
        q = q.filter_by(product=product)
    return q.order_by(ObjectAbsence.last_seen_at.desc()).all()


def actionable(product: str = "", *, since_hours: int = 0) -> list:
    """Open rows whose verdict names work SATOM must do to ITSELF.

    ``since_hours`` narrows to recently re-proved rows; 0 means all. The alert
    engine uses it so a finding that stopped being re-proved (the evidence
    changed, the object came back) stops firing without anybody clearing it.
    """
    rows = [r for r in open_findings(product)
            if corr.is_actionable(r.state)]
    if since_hours:
        cutoff = datetime.utcnow() - timedelta(hours=since_hours)
        rows = [r for r in rows if (r.last_seen_at or cutoff) >= cutoff]
    return rows


def counts(findings) -> dict:
    """``{state: n}`` over a list of finding dicts or rows — one counter.

    Accepts both shapes because the page counts what it just rendered (dicts)
    and the ledger page counts rows, and two spellings of the same tally is how
    a header learns to disagree with the table under it.
    """
    out = {}
    for f in findings or []:
        state = f.get("state") if isinstance(f, dict) else getattr(f, "state", "")
        out[state] = out.get(state, 0) + 1
    return out


# ---------------------------------------------------------------------------
# review
# ---------------------------------------------------------------------------
def review(row_id: int, decision: str, *, actor: str = "",
           note: str = "") -> tuple:
    """Accept or refuse one finding. ``(ok, message, row)``.

    ``decision`` is ``acknowledge`` or ``dismiss``. There is deliberately no
    ``apply`` verb: see :data:`BLOCKED_REASON`. Offering one that always
    refuses would be a control that teaches the operator it is broken.
    """
    row = db.session.get(ObjectAbsence, row_id)
    if row is None:
        return False, "No such finding.", None
    if decision not in ("acknowledge", "dismiss"):
        return False, "Unknown decision %r." % decision, row
    row.correction = (CORR_APPLIED if decision == "acknowledge"
                      else CORR_DISMISSED)
    row.correction_note = note or (
        BLOCKED_REASON if row.proposed_path else "")
    row.reviewed_by = actor or "unknown"
    row.reviewed_at = datetime.utcnow()
    try:
        db.session.commit()
    except Exception as exc:  # noqa: BLE001
        db.session.rollback()
        return False, str(exc), row
    return True, "Finding %sd." % decision, row


__all__ = ["K_AUTOACK", "K_ENABLED", "BLOCKED_REASON", "line_pairs",
           "evaluate", "record", "open_findings", "actionable", "counts",
           "review"]
