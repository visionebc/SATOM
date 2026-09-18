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
from . import api_matrix, cli_coverage, firmware_versions

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

    The numeric half is DELEGATED to :func:`firmware_versions.sort_key` rather
    than re-implemented. This module used to carry its own integer split, which
    is two spellings of one ordering in a codebase where the page sorts with
    one of them and the ledger pairs with the other: the day they disagree,
    ``line_pairs`` pairs lines the page lists in a different order and every
    added/removed verdict between them flips, silently. Unparseable scopes keep
    their old place (last, ordered by text) because that property is what stops
    a junk line from sorting itself in front of 7.6 and stealing its pair.
    """
    v = firmware_versions.normalize(scope)
    if not v:
        return (1, (), str(scope or ""))
    return (0, firmware_versions.sort_key(v), "")


def line_pairs(product: str, matrix: dict | None = None) -> list[tuple]:
    """Adjacent ``(older, newer)`` line pairs for a product.

    ADJACENT, not every combination: 7.6 -> 8.0 -> 8.2 asks two questions and
    the cross pair 7.6 -> 8.2 asks a third that is already answered by the
    other two and would double-count every object removed in 8.0. Lines rather
    than builds, because a ledger keyed on builds grows a row per patch release
    for a fact that is true of the line.
    """
    matrix = matrix if matrix is not None else resolved_matrix(product)
    lines = sorted((matrix.get("lines") or {}).keys(), key=_version_key)
    return list(zip(lines, lines[1:]))


def resolved_matrix(product: str) -> dict:
    """The matrix this module pairs lines from: DERIVED evidence + DECLARATIONS.

    The same object the comparison page resolves, and that identity is the
    whole point. The page reads ``firmware_versions.overlay(...)``; this module
    used to read the raw file. Two readers of "which firmware lines exist"
    means the reader and the writer of the ledger can disagree about which
    pairs are adjacent -- and the disagreement appears the moment a line is
    known but not yet swept, which is exactly what a NEW firmware release is.
    A box upgraded to 8.1, or a version typed into the declare form, changes
    the page's pairing and used to leave the recorder pairing the old way.

    A declared-but-unmeasured line contributes no findings (there is no
    evidence to diff), so sharing the list costs nothing and buys the
    guarantee that both halves answer "adjacent?" identically.
    """
    try:
        return firmware_versions.overlay(product, api_matrix.load(product) or {})
    except Exception:  # noqa: BLE001 -- no app context / unreadable DB
        # The declarations live in Postgres and the evidence in a file. If the
        # database cannot be read we still pair from the file rather than
        # returning nothing: fewer lines is a smaller answer, no lines is a
        # wrong one (every pair would look orphaned).
        return api_matrix.load(product) or {}


def _evaluate_pair(product: str, base: str, target: str,
                   matrix: dict | None = None) -> list[dict]:
    """Corroborated verdicts for one line pair. Pure read, no DB writes."""
    delta = api_matrix.diff(product, base, target, matrix=matrix)
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
    """Every corroborated verdict for a product, across adjacent line pairs.

    The pairs and the deltas are read off ONE matrix, resolved once. Pairing
    from one view of the lines and diffing against another is how a pair could
    be evaluated against a scope the pairing never saw.
    """
    findings = []
    matrix = resolved_matrix(product)
    for base, target in line_pairs(product, matrix):
        try:
            findings.extend(_evaluate_pair(product, base, target, matrix))
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
# joining the ledger to a comparison
# ---------------------------------------------------------------------------
#: One vocabulary for the review state of a ledger row: (text, css, title).
#: Spelled HERE and nowhere else. ``correction`` is a storage value; a second
#: spelling of it inside a template is how a badge drifts away from the column
#: it is supposed to mirror -- the failure this page has already been bitten by
#: twice with the provenance labels.
REVIEW_LABEL = {
    CORR_NONE: (
        "needs review", "fw-badge-warning",
        "Recorded and still open: nobody has accepted or refused this finding "
        "yet."),
    CORR_PROPOSED: (
        "needs review", "fw-badge-danger",
        "Recorded and open, and the configuration dump on that line spells the "
        "path differently. The alternative spelling is evidence for a person, "
        "never a value this page will write."),
    CORR_APPLIED: (
        "accepted", "fw-badge-success",
        "A decision is on the record: the disappearance is taken as true of "
        "the firmware. No catalogue entry was rewritten -- the finding is "
        "about the firmware, not about the entry."),
    CORR_DISMISSED: (
        "refused", "fw-badge-secondary",
        "A person looked and refused this finding. The row is kept rather than "
        "deleted, so the refusal is itself on the record and the next sweep "
        "does not re-open it."),
}

#: Why a comparison has NO ledger scope. Spelled out rather than left as an
#: empty result: "the ledger recorded nothing for this pair" and "this pair is
#: not a thing the ledger tracks" render identically as blank and mean opposite
#: things -- the same confusion as a gap printed like a measured no.
LEDGER_SAME_LINE = (
    "Both sides of this comparison are builds of the SAME firmware line, and a "
    "disappearance is recorded against the line that removed it. The ledger "
    "therefore has nothing to say here, which is not a claim that nothing "
    "disappeared between these two builds.")
LEDGER_NOT_ADJACENT = (
    "The ledger records ADJACENT line pairs only, so that an object removed "
    "once is not counted again by every later comparison that skips over the "
    "line which removed it. Compare the adjacent lines to see its record.")
LEDGER_ORPHANED = (
    "These rows were recorded when this pair WAS adjacent. A firmware line has "
    "since appeared between the two, so the ledger no longer tracks this pair "
    "and nothing re-proves these findings. They are shown here, on the "
    "comparison that recorded them, because the alternative is that a decision "
    "somebody took disappears from every screen the day a new firmware ships.")
LEDGER_UNSCOPED = (
    "This comparison does not resolve to two firmware lines, so there is no "
    "line pair for the ledger to answer about.")


def _pair_has_rows(product: str, base_line: str, target_line: str) -> bool:
    """True when the ledger holds any row filed under this exact pair."""
    try:
        return db.session.query(
            ObjectAbsence.query.filter_by(
                product=product, base_scope=base_line,
                target_scope=target_line).exists()).scalar() or False
    except Exception:  # noqa: BLE001 -- an unreadable ledger holds nothing
        db.session.rollback()
        return False


def ledger_scope(product: str, base: str, target: str,
                 matrix: dict | None = None) -> tuple:
    """``(base_line, target_line, note)`` the ledger answers for this pair.

    The comparison defaults to two BUILDS and the ledger is keyed on LINES, so
    the join is made explicit here and the resolved scopes are handed back to
    be PRINTED. A row found this way is about ``7.6 -> 8.0``; rendering it
    against ``7.6.8 -> 8.0.5`` without naming its own scopes would let a line
    rollup borrow a build's authority -- the exact boundary
    :mod:`app.models_lifecycle` stores both scopes verbatim to defend.
    """
    lb = firmware_versions.line_of(base or "")
    lt = firmware_versions.line_of(target or "")
    if not lb or not lt:
        return "", "", LEDGER_UNSCOPED
    if lb == lt:
        return "", "", LEDGER_SAME_LINE
    if (lb, lt) not in line_pairs(product, matrix):
        return "", "", LEDGER_NOT_ADJACENT
    return lb, lt, ""


def orphans(product: str, matrix: dict | None = None) -> list[dict]:
    """Recorded line pairs that are no longer adjacent. One entry per pair.

    A firmware line that lands BETWEEN two recorded ones re-pairs the whole
    ledger: ``7.6 -> 8.0`` stops being adjacent the moment ``7.8`` exists, and
    every row filed under it -- including the ones a person accepted or refused
    -- becomes unreachable from every comparison while :func:`evaluate` stops
    re-proving them. Nothing raises and nothing is logged; the decisions simply
    stop existing as far as the product is concerned. Measured on 2026-09-18
    against the live ledger: inserting one line turned five decided rows into
    zero visible rows, in silence.

    Rows are never RE-KEYED onto the new pairing. A decision was taken about
    the pair it names, and moving it would put a person's name on a judgement
    they did not make -- the same reason a refusal is kept rather than deleted.

    An empty ``line_pairs`` (unreadable matrix, a product never swept) returns
    ``[]`` rather than "everything is orphaned": not knowing which pairs are
    adjacent is not evidence that none are, and a check that cries wolf on a
    cold start is one that gets muted before it is ever right.
    """
    pairs = set(line_pairs(product, matrix))
    if not pairs:
        return []
    try:
        rows = ObjectAbsence.query.filter_by(product=product).all()
    except Exception:  # noqa: BLE001 -- see ledger_for_pair's docstring
        db.session.rollback()
        return []
    groups: dict = {}
    for r in rows:
        key = (r.base_scope or "", r.target_scope or "")
        if key in pairs:
            continue
        g = groups.setdefault(key, {"base": key[0], "target": key[1],
                                    "rows": 0, "open": 0, "decided": 0,
                                    "names": [], "last_seen_at": None})
        g["rows"] += 1
        if is_open(r):
            g["open"] += 1
        else:
            g["decided"] += 1
        g["names"].append(r.name)
        if r.last_seen_at and (g["last_seen_at"] is None
                               or r.last_seen_at > g["last_seen_at"]):
            g["last_seen_at"] = r.last_seen_at
    for g in groups.values():
        g["names"].sort()
    return sorted(groups.values(),
                  key=lambda g: (_version_key(g["base"]), _version_key(g["target"])))


def ledger_for_pair(product: str, base: str, target: str,
                    matrix: dict | None = None) -> dict:
    """The ledger rows this comparison can speak for, keyed by object name.

    ``{"rows": {name: ObjectAbsence}, "base", "target", "note", "open",
    "borrowed"}``. ``borrowed`` is True when the ledger's scopes are not the
    ones on screen -- the page has to SAY so, because a review decision taken
    here is recorded against the line pair, not against the two builds the
    operator happens to be looking at.

    A database that cannot be read (the read-only standby mid-failover, a
    missing table on an un-migrated node) yields no rows and no exception: the
    comparison is the page's job and the ledger is an annotation on it.
    """
    lb, lt, note = ledger_scope(product, base, target, matrix)
    orphaned = False
    if not lb and note is LEDGER_NOT_ADJACENT:
        # The pair does not pair TODAY. That has two causes and they need
        # opposite words: a comparison that deliberately skips a line (its
        # record lives in the adjacent pairs -- go read those), or a pair that
        # WAS adjacent until a line appeared between its two halves, whose
        # rows now live nowhere else at all. Answering the second with the
        # first's advice sends the operator to look for decisions in a pair
        # that never held them.
        cb, ct = (firmware_versions.line_of(base or ""),
                  firmware_versions.line_of(target or ""))
        if cb and ct and _pair_has_rows(product, cb, ct):
            lb, lt, note, orphaned = cb, ct, LEDGER_ORPHANED, True
    out = {"rows": {}, "base": lb, "target": lt, "note": note, "open": 0,
           "reviewed": 0, "orphaned": orphaned,
           "borrowed": bool(lb) and (lb != base or lt != target)}
    if not lb:
        return out
    try:
        rows = ObjectAbsence.query.filter_by(
            product=product, base_scope=lb, target_scope=lt).all()
    except Exception:  # noqa: BLE001 -- see docstring
        db.session.rollback()
        return out
    out["rows"] = {r.name: r for r in rows}
    for r in rows:
        if (r.correction or CORR_NONE) in (CORR_NONE, CORR_PROPOSED):
            out["open"] += 1
        else:
            out["reviewed"] += 1
    return out


def review_label(row) -> tuple:
    """The (text, css, title) triple for one row's review state."""
    return REVIEW_LABEL.get(getattr(row, "correction", "") or CORR_NONE,
                            REVIEW_LABEL[CORR_NONE])


def is_open(row) -> bool:
    """True while a finding still waits for a person.

    One predicate, used by the queue, the counter and the template gate. Three
    spellings of ``correction in (none, proposed)`` is how a header learns to
    disagree with the buttons under it.
    """
    return (getattr(row, "correction", "") or CORR_NONE) in (CORR_NONE,
                                                             CORR_PROPOSED)


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


__all__ = ["K_AUTOACK", "K_ENABLED", "BLOCKED_REASON", "REVIEW_LABEL",
           "LEDGER_SAME_LINE", "LEDGER_NOT_ADJACENT", "LEDGER_ORPHANED",
           "LEDGER_UNSCOPED", "orphans", "resolved_matrix",
           "line_pairs", "evaluate", "record", "open_findings", "actionable",
           "counts", "review", "ledger_scope", "ledger_for_pair",
           "review_label", "is_open"]
