"""Batch backend reachability from a list of ``source;policy;destination``.

The operator has a file (or a textarea) of triples and one question per line:
**do the real servers behind this policy answer — on the source box, and then
on the destination box?** Nothing here writes. Not to an appliance, not to the
database. The only traffic it emits is ``execute ping`` over the read-only CLI
and TCP handshakes from this node.

WHY IT IS ITS OWN PAGE, NOT A CHECKBOX ON THE CLONE DIALOG
    ``policy_ops.probe_backends_after`` answers the same question but only
    AFTER a write, on ONE destination, for the policies that write just
    touched. This one runs standalone: many sources, many destinations, no
    workspace tab open, and no appliance selected anywhere.

WHAT IT DOES NOT RE-IMPLEMENT
    Reading a policy's pool members is :func:`backend_probe.dst_pool_targets`;
    probing one target is :func:`backend_probe.probe_targets`; deciding whether
    a backend counts as reachable is :func:`backend_probe.classify_row`. This
    module supplies ORDER (source first, then destination), GROUPING (one API
    read per appliance however many lines name it), CACHING and the per-line
    verdict. A second copy of any of those judgements would let this page and
    the clone report disagree about the same backend.

THE THREE RULES THIS FILE EXISTS TO HOLD
    1. **A probe that could not run is never an outage.** It is ``unknown``,
       counted in its own bucket, all the way up to the line verdict.
    2. **A bad destination does not void the source answer.** The source half
       is read and reported even when the destination name is unknown, the box
       is unreachable, or the policy is not there. Half an answer beats none,
       and the source half is the reference the operator is comparing against.
    3. **Nothing is dropped silently.** Over-limit lines, header lines, targets
       cut by the target cap and backends skipped when the time budget expired
       are each reported by name. A report that quietly covers less than it was
       asked to reads exactly like a clean run.
"""
from __future__ import annotations

import time

from . import backend_probe as _bp

#: Hard caps. Each one is REPORTED when it bites (``dropped`` / ``capped`` /
#: ``budget_hit``) — see rule 3 above.
MAX_LINES = 200
MAX_TARGETS = 2000
DEFAULT_BUDGET_S = 120.0
MAX_BUDGET_S = 300.0
DEFAULT_TCP_TIMEOUT = 2.0

#: Probing is chunked so the time budget is checked often. A single appliance
#: with 400 members and a 3 s timeout would otherwise blow any budget checked
#: once per appliance.
_CHUNK = 20

#: Lines that ARE the format, not data. An operator who pastes the documented
#: example as line 1 of their file is not asking for an appliance called
#: "source fortiweb", and answering "no such device" to the header is a false
#: finding at the top of every report.
_HEADER_LINES = {
    "source;spo;destination",
    "source;policy;destination",
    "source fortiweb;spo;destination fortiweb",
    "source fortiweb;spo;destination fortiadc",
}

#: Verdicts, worst first. A line carries ONE verdict and every finding it
#: earned; the verdict is the worst severity among the findings.
VERDICTS = ("error", "down", "mismatch", "unknown", "ok")
_SEVERITY = {v: i for i, v in enumerate(reversed(VERDICTS))}  # ok=0 … error=4

#: finding code -> the verdict it implies. ``no_destination`` maps to ``ok``
#: on purpose: a two-field line asked a source-only question and got a
#: source-only answer. That is a complete answer, not a degraded one.
_CODE_VERDICT = {
    "line_error": "error",
    "source_unresolved": "error",
    "source_unreadable": "error",
    "destination_unresolved": "error",
    "destination_unreadable": "error",
    "policy_absent_on_source": "error",
    "pool_unreadable": "error",
    "unreachable": "down",
    "policy_absent_on_destination": "mismatch",
    "missing_in_destination": "mismatch",
    "extra_in_destination": "mismatch",
    "no_pool": "mismatch",
    "empty_pool": "mismatch",
    "all_members_disabled": "mismatch",
    "no_vantage": "unknown",
    "comparison_skipped": "unknown",
    "no_destination": "ok",
}


# --------------------------------------------------------------------------- #
#  Parsing — pure, no appliance and no database                                 #
# --------------------------------------------------------------------------- #
def _header(line: str) -> bool:
    return ";".join(p.strip().lower() for p in line.split(";")) in _HEADER_LINES


def parse_batch(text: str, *, max_lines: int = MAX_LINES) -> tuple:
    """``text`` → ``(rows, dropped)``.

    One row per DATA line, in file order, each carrying its 1-based ``lineno``
    so the report points at the operator's file and not at an index of its own.
    A malformed line becomes a row with ``error`` set — never a missing row,
    because a report with fewer lines than the file reads as "all fine".
    """
    rows: list = []
    dropped: list = []
    body = (text or "").lstrip("﻿").replace("\r\n", "\n").replace("\r", "\n")
    for n, raw in enumerate(body.split("\n"), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if _header(line):
            dropped.append({"lineno": n, "raw": line,
                            "why": "this is the format header, not a line to check"})
            continue
        if len(rows) >= max_lines:
            dropped.append({"lineno": n, "raw": line,
                            "why": "over the %d-line limit for one run — split "
                                   "the file and run it again" % max_lines})
            continue
        parts = [p.strip() for p in line.split(";")]
        if len(parts) == 2:
            parts.append("")
        row = {"lineno": n, "raw": line, "source": "", "policy": "",
               "destination": "", "error": ""}
        if len(parts) != 3:
            row["error"] = ("expected 'source;policy;destination' — this line "
                            "has %d field%s separated by ';'"
                            % (len(parts), "" if len(parts) == 1 else "s"))
            rows.append(row)
            continue
        row["source"], row["policy"], row["destination"] = parts
        if not row["source"]:
            row["error"] = "no source appliance on this line"
        elif not row["policy"]:
            row["error"] = "no server policy on this line"
        rows.append(row)
    return rows, dropped


def build_index(appliances) -> dict:
    """Lowercased name/host → appliance.

    Names are indexed for EVERY appliance before any host is, so a device whose
    host happens to equal another device's name can never shadow that name.
    First-wins inside one pass keeps the mapping independent of query order —
    a lookup that changes answer with row order is not a lookup.
    """
    idx: dict = {}
    for a in appliances or []:
        key = str(getattr(a, "name", "") or "").strip().lower()
        if key:
            idx.setdefault(key, a)
    for a in appliances or []:
        key = str(getattr(a, "host", "") or "").strip().lower()
        if key:
            idx.setdefault(key, a)
    return idx


def resolve(name: str, index: dict) -> tuple:
    """``(appliance, error)`` — never raises, never guesses.

    A device registered on a ``*.invalid`` placeholder host is refused HERE,
    before a client is built: those are the retired rows, and letting the read
    go out spends a connect timeout per line to learn what the registry already
    says.
    """
    key = str(name or "").strip().lower()
    if not key:
        return None, "no appliance name given"
    appl = index.get(key)
    if appl is None:
        return None, ("no appliance is registered as %r in this ADOM" % name)
    kind = str(getattr(appl, "kind", "") or "fortiweb").strip().lower()
    if kind != "fortiweb":
        return None, ("%s is a %s — this check reads FortiWeb server policies"
                      % (getattr(appl, "name", name), kind))
    host = str(getattr(appl, "host", "") or "").strip()
    if host.lower().endswith(".invalid"):
        return None, ("%s is registered on the placeholder host %s — it is a "
                      "retired device, not something to probe"
                      % (getattr(appl, "name", name), host))
    return appl, ""


# --------------------------------------------------------------------------- #
#  Running                                                                      #
# --------------------------------------------------------------------------- #
def _blank_side(reason: str = "not checked") -> dict:
    return {"ran": False, "reason": reason, "appliance": "", "ssh": False,
            "rows": [], "summary": _bp.summarise([]), "from_source_pool": False}


def _skipped(targets, why: str) -> list:
    """Targets the run never got to, in the SAME shape a probed row has.

    Built from :data:`backend_probe.NOT_PROBED` rather than from a fresh
    literal: a second spelling of "not probed" is how it stops being counted as
    unknown and starts being counted as nothing at all.
    """
    out = []
    for t in targets:
        row = dict(t)
        row["appliance"] = dict(_bp.NOT_PROBED)
        row["local"] = {"ok": False, "verdict": "not probed", "detail": why}
        out.append(row)
    return out


def _members(rows) -> set:
    """The (address, port) pairs a side actually has. Error rows are not members."""
    return {(str(r.get("address") or ""), r.get("port"))
            for r in rows or [] if not r.get("error") and r.get("address")}


def run_batch(rows, *, use_ssh: bool = False,
              tcp_timeout: float = DEFAULT_TCP_TIMEOUT,
              budget_s: float = DEFAULT_BUDGET_S, user=None,
              appliances=None, client_factory=None, ssh_factory=None,
              clock=time.monotonic) -> dict:
    """Probe every line's source, then its destination. Returns the report.

    ``appliances`` / ``client_factory`` / ``ssh_factory`` / ``clock`` are
    injection seams for the tests; production passes none of them. ``clock``
    exists so the budget can be tested without monkeypatching ``time`` for
    the whole process — patching the global clock to test one branch breaks
    every other thing in the run that reads it.

    SOURCES ARE READ BEFORE DESTINATIONS. Not decoration: the source pool is
    the reference the destination is compared against, and when the budget runs
    out it is the half that must already be on the page.
    """
    t0 = clock()
    budget = max(5.0, min(float(budget_s or DEFAULT_BUDGET_S), MAX_BUDGET_S))
    deadline = t0 + budget
    report = {"lines": [], "dropped": [], "capped": [], "appliances": [],
              "budget_hit": False, "elapsed_s": 0.0,
              "vantages": {"appliance": bool(use_ssh), "local": True},
              "totals": {v: 0 for v in VERDICTS}}

    if appliances is None:
        from ..models import visible_appliances
        appliances = visible_appliances(user=user).all()
    index = build_index(appliances)

    if client_factory is None:
        from ..clients.fortiweb import FortiWebClient
        client_factory = FortiWebClient
    if ssh_factory is None:
        def ssh_factory(appl):  # noqa: E306
            from . import ssh_ops
            return ssh_ops.FortiWebReadonlySSH(appl, timeout=20.0).connect()

    # -- resolve every name once ------------------------------------------- #
    for r in rows:
        r["_src"] = r["_dst"] = None
        r["_dst_error"] = ""
        if r.get("error"):
            continue
        appl, err = resolve(r["source"], index)
        if err:
            r["error"] = err
            continue
        r["_src"] = appl
        if r["destination"]:
            appl, err = resolve(r["destination"], index)
            # Rule 2: a destination we cannot resolve is recorded and the
            # source half still runs.
            if err:
                r["_dst_error"] = err
            else:
                r["_dst"] = appl

    # -- group: one API read per appliance, sources first ------------------- #
    order: list = []
    wanted: dict = {}
    for key in ("_src", "_dst"):
        for r in rows:
            appl = r.get(key)
            if appl is None:
                continue
            aid = getattr(appl, "id", None) or getattr(appl, "name", "")
            if aid not in wanted:
                wanted[aid] = {"appl": appl, "policies": set()}
                order.append(aid)
            wanted[aid]["policies"].add(r["policy"])

    tcp_cache: dict = {}          # (addr, port) -> result. Vantage: THIS node.
    ping_caches: dict = {}        # aid -> {addr: result}. Vantage: that box ONLY.
    sessions: dict = {}
    reads: dict = {}
    spent = 0

    try:
        for aid in order:
            appl = wanted[aid]["appl"]
            name = str(getattr(appl, "name", "") or "")
            entry = {"name": name, "error": "", "ssh": False, "ssh_error": "",
                     "by_policy": {}}
            reads[aid] = entry
            report["appliances"].append(entry)
            try:
                targets = _bp.dst_pool_targets(client_factory(appl),
                                               sorted(wanted[aid]["policies"]))
            except Exception as exc:  # noqa: BLE001
                entry["error"] = "could not read the server policies: %s" % exc
                continue

            sess = None
            if use_ssh:
                try:
                    sess = ssh_factory(appl)
                    sessions[aid] = sess
                    entry["ssh"] = True
                except Exception as exc:  # noqa: BLE001
                    # The appliance vantage is lost for THIS box, not the run:
                    # the TCP probe from this node still tells "port shut"
                    # apart from "host gone".
                    entry["ssh_error"] = str(exc)
            ping_caches[aid] = {}

            # A capped target is CARRIED as ``not probed``, not deleted. Deleting
            # it would leave its line showing a shorter pool that is entirely
            # green — a cap that reads as a clean result is the worst possible
            # way to run out of room.
            room = max(MAX_TARGETS - spent, 0)
            over = targets[room:]
            targets = targets[:room]
            if over:
                report["capped"].append({
                    "appliance": name, "dropped": len(over),
                    "why": "the %d-target cap for one run" % MAX_TARGETS})
            spent += len(targets)

            probed: list = []
            for i in range(0, len(targets), _CHUNK):
                chunk = targets[i:i + _CHUNK]
                if clock() >= deadline:
                    report["budget_hit"] = True
                    probed.extend(_skipped(
                        targets[i:], "the run's %ds time budget expired before "
                                     "this backend" % int(budget)))
                    break
                probed.extend(_bp.probe_targets(
                    chunk, ssh_session=sess, tcp_timeout=tcp_timeout,
                    ping_cache=ping_caches[aid], tcp_cache=tcp_cache))
            probed.extend(_skipped(
                over, "the %d-target cap for one run was reached before this "
                      "backend" % MAX_TARGETS))
            for row in probed:
                entry["by_policy"].setdefault(str(row.get("policy") or ""),
                                              []).append(row)

        # -- assemble one result per line ----------------------------------- #
        for r in rows:
            report["lines"].append(_assemble(
                r, reads, sessions, ping_caches, tcp_cache,
                tcp_timeout=tcp_timeout, deadline=deadline, report=report,
                clock=clock))
    finally:
        for sess in sessions.values():
            try:
                sess.close()
            except Exception:  # noqa: BLE001
                pass

    for line in report["lines"]:
        report["totals"][line["verdict"]] = report["totals"].get(
            line["verdict"], 0) + 1
    report["elapsed_s"] = round(clock() - t0, 1)
    return report


def _side_for(appl, reads, policy: str) -> dict:
    aid = getattr(appl, "id", None) or getattr(appl, "name", "")
    entry = reads.get(aid)
    side = _blank_side()
    side["appliance"] = str(getattr(appl, "name", "") or "")
    if entry is None:
        side["reason"] = "this appliance was never read"
        return side
    side["ssh"] = bool(entry.get("ssh"))
    if entry.get("error"):
        side["reason"] = entry["error"]
        return side
    rows = _stamp(entry["by_policy"].get(policy, []))
    side["ran"] = True
    side["rows"] = rows
    side["summary"] = _bp.summarise(rows)
    return side


def _stamp(rows):
    """Put ``state`` on every row so the TEMPLATE never judges a backend.

    The value comes from :func:`backend_probe.classify_row` — the same call
    :func:`backend_probe.summarise` counts with. A Jinja expression that
    re-derived "is this green?" from ``appliance``/``local`` would be a second
    author of the rule, and the first symptom would be a table of green rows
    under a red summary.
    """
    for row in rows or []:
        row["state"] = _bp.classify_row(row)
    return rows


def _kinds(side) -> set:
    return {str(x.get("error_kind") or "") for x in side["rows"]
            if x.get("error_kind")}


def _assemble(r, reads, sessions, ping_caches, tcp_cache, *, tcp_timeout,
              deadline, report, clock=time.monotonic) -> dict:
    """One parsed line + the reads → its two sides, its findings, its verdict."""
    out = {"lineno": r["lineno"], "raw": r["raw"], "source": r["source"],
           "policy": r["policy"], "destination": r["destination"],
           "error": r.get("error", ""), "findings": [], "verdict": "ok",
           "src": _blank_side(), "dst": _blank_side()}
    # Each finding carries the verdict it implies, resolved HERE from
    # _CODE_VERDICT. The template renders that value; letting a Jinja
    # expression map codes to colours would be the second author of the
    # severity table, and it would drift the first time a code is added.
    add = lambda code, text: out["findings"].append(  # noqa: E731
        {"code": code, "text": text,
         "verdict": _CODE_VERDICT.get(code, "unknown")})

    if out["error"]:
        add("line_error", out["error"])
        out["verdict"] = "error"
        return out

    # -- source first ------------------------------------------------------ #
    out["src"] = _side_for(r["_src"], reads, r["policy"])
    if not out["src"]["ran"]:
        add("source_unreadable", "source %s: %s"
            % (out["src"]["appliance"], out["src"]["reason"]))
    else:
        src_kinds = _kinds(out["src"])
        if "no_such_policy" in src_kinds:
            add("policy_absent_on_source",
                "%s does not have a server policy called %r"
                % (out["src"]["appliance"], r["policy"]))
        if "pool_unreadable" in src_kinds:
            add("pool_unreadable", "source %s: the pool members could not be read"
                % out["src"]["appliance"])
        if "no_pool" in src_kinds:
            add("no_pool", "source %s: the policy names no server pool"
                % out["src"]["appliance"])
        if "empty_pool" in src_kinds:
            add("empty_pool", "source %s: the pool has no real servers"
                % out["src"]["appliance"])
        _reachability_findings(out["src"], "source", add)

    # -- then the destination ---------------------------------------------- #
    if r.get("_dst_error"):
        add("destination_unresolved", r["_dst_error"])
        out["dst"]["reason"] = r["_dst_error"]
    elif r["_dst"] is None:
        add("no_destination", "no destination on this line — the source half "
                              "is the whole answer here")
        out["dst"]["reason"] = "no destination given"
    else:
        out["dst"] = _side_for(r["_dst"], reads, r["policy"])
        if not out["dst"]["ran"]:
            add("destination_unreadable", "destination %s: %s"
                % (out["dst"]["appliance"], out["dst"]["reason"]))
        else:
            dst_kinds = _kinds(out["dst"])
            if "no_such_policy" in dst_kinds:
                add("policy_absent_on_destination",
                    "%s does not have a server policy called %r"
                    % (out["dst"]["appliance"], r["policy"]))
                _fallback_from_source(r, out, reads, sessions, ping_caches,
                                      tcp_cache, tcp_timeout=tcp_timeout,
                                      deadline=deadline, report=report,
                                      clock=clock)
            if "pool_unreadable" in dst_kinds:
                add("pool_unreadable",
                    "destination %s: the pool members could not be read"
                    % out["dst"]["appliance"])
            if "no_pool" in dst_kinds:
                add("no_pool", "destination %s: the policy names no server pool"
                    % out["dst"]["appliance"])
            if "empty_pool" in dst_kinds:
                add("empty_pool", "destination %s: the pool has no real servers"
                    % out["dst"]["appliance"])
            _reachability_findings(out["dst"], "destination", add)
            _compare(out, add)

    sev = max((_SEVERITY.get(f["verdict"], 1) for f in out["findings"]),
              default=0)
    out["verdict"] = VERDICTS[len(VERDICTS) - 1 - sev]
    return out


def _reachability_findings(side, label: str, add) -> None:
    """Per-side findings that come from the probes themselves.

    ``unknown`` only becomes a finding when NOTHING on this side came back
    conclusive. One unknown among nine reachable backends is a detail of the
    table, not a verdict on the line.
    """
    s = side["summary"]
    real = [x for x in side["rows"] if not x.get("error")]
    if s["unreachable"]:
        add("unreachable", "%s %s: %d of %d backend%s did not answer"
            % (label, side["appliance"], s["unreachable"], s["total"],
               "" if s["total"] == 1 else "s"))
    elif real and s["reachable"] == 0 and s["unknown"]:
        add("no_vantage", "%s %s: no vantage could test any of its %d backend%s "
                          "— this is NOT evidence they are down"
            % (label, side["appliance"], s["unknown"],
               "" if s["unknown"] == 1 else "s"))
    if real and s["disabled"] == len(real):
        add("all_members_disabled", "%s %s: every member of the pool is disabled"
            % (label, side["appliance"]))


def _compare(out, add) -> None:
    """Source pool vs destination pool, by (address, port).

    SKIPPED when the destination rows came from the SOURCE's pool (the
    fallback below): comparing a list against itself always agrees, and an
    agreement nobody measured is worse than no comparison at all.

    And the skip is SAID, not just done. A silent early return here produced a
    line with no mismatch findings, which reads exactly like a line whose pools
    were compared and matched — the one thing this function must never imply.
    """
    if out["dst"].get("from_source_pool"):
        add("comparison_skipped",
            "the destination has no pool of its own for this policy, so there "
            "is nothing to compare the source's members against")
        return
    if not out["src"]["ran"]:
        return
    src, dst = _members(out["src"]["rows"]), _members(out["dst"]["rows"])
    if not src and not dst:
        return
    missing = sorted(src - dst)
    extra = sorted(dst - src)
    if missing:
        add("missing_in_destination",
            "the destination pool is missing %s"
            % ", ".join("%s:%s" % (a, p) for a, p in missing[:8]))
    if extra:
        add("extra_in_destination",
            "the destination pool has %s, which the source does not"
            % ", ".join("%s:%s" % (a, p) for a, p in extra[:8]))


def _fallback_from_source(r, out, reads, sessions, ping_caches, tcp_cache, *,
                          tcp_timeout, deadline, report,
                          clock=time.monotonic) -> None:
    """Destination has no such policy → ping the SOURCE's backends FROM it.

    This is the pre-migration question ("before I clone, can the new box even
    reach these servers?") and it is a DIFFERENT measurement from the one every
    other destination row carries — so the side is flagged ``from_source_pool``
    and the comparison is skipped. Only runs with an SSH vantage: without one
    the only probe left is TCP from this node, which would repeat the source's
    own answer and say nothing at all about the destination.
    """
    aid = getattr(r["_dst"], "id", None) or getattr(r["_dst"], "name", "")
    sess = sessions.get(aid)
    if sess is None or not out["src"]["ran"]:
        return
    targets = [{k: v for k, v in row.items()
                if k not in ("appliance", "local")}
               for row in out["src"]["rows"] if not row.get("error")]
    if not targets:
        return
    if clock() >= deadline:
        report["budget_hit"] = True
        rows = _skipped(targets, "the run's time budget expired before this "
                                 "backend")
    else:
        rows = _bp.probe_targets(targets, ssh_session=sess,
                                 tcp_timeout=tcp_timeout,
                                 ping_cache=ping_caches.setdefault(aid, {}),
                                 tcp_cache=tcp_cache)
    out["dst"]["ran"] = True
    out["dst"]["from_source_pool"] = True
    out["dst"]["rows"] = _stamp(rows)
    out["dst"]["summary"] = _bp.summarise(rows)
    out["dst"]["reason"] = ("the policy is not on this box — these are the "
                            "SOURCE's backends, pinged from the destination")


# --------------------------------------------------------------------------- #
#  Export                                                                       #
# --------------------------------------------------------------------------- #
_TSV_HEADER = ("line\tsource\tpolicy\tdestination\tverdict\t"
               "src reachable/down/unknown\tdst reachable/down/unknown\tfindings")


def to_tsv(report) -> str:
    """The report as one row per line, for a ticket or a spreadsheet."""
    def counts(side):
        if not side["ran"]:
            return "not read"
        s = side["summary"]
        return "%d/%d/%d" % (s["reachable"], s["unreachable"], s["unknown"])

    out = [_TSV_HEADER]
    for ln in report.get("lines", []):
        out.append("\t".join([
            str(ln["lineno"]), ln["source"], ln["policy"],
            ln["destination"] or "—", ln["verdict"],
            counts(ln["src"]), counts(ln["dst"]),
            "; ".join(f["text"] for f in ln["findings"]) or "—",
        ]))
    return "\n".join(out)
