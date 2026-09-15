"""Batch discovery — promote the CLI-only findings into catalog entries the
DEVICE has confirmed, a whole dump at a time instead of one form at a time.

WHY THIS EXISTS. The endpoint catalog only knew how to SHRINK by itself:
:mod:`app.services.registry_reconcile` reads the sweep ledger and proposes
DISABLING names no appliance serves, while growing it meant typing one
``registry.save`` form per entry. The CLI↔API coverage diff routinely finds 50+
blocks the catalog does not know, so "add them by hand" is operationally the
same sentence as "they never get added".

WHAT THIS MAY NOT DO — and the reason the whole module is shaped around it.
It may not DERIVE a REST path and write it. The catalog is what every service
resolves names through (``loader.resolve``), so a guessed URL behind a friendly
key does not fail here: it fails later, somewhere else, as a phantom endpoint,
and by then nothing points back at the guess. Therefore this module only ever
ASKS the appliance — through :func:`app.services.rediscovery.probe_endpoint`,
the same three verdicts the sweep and the reconciler already act on — and
reports what it answered. Registration is gated on ``verdict == ok``.

THREE NEGATIVES THAT MUST NEVER MERGE, because each sends the operator
somewhere different:

* ``absent``     — the device answered, and the answer is "that path does not
                   exist". A real, useful negative: the candidate is wrong.
* ``error``      — we failed to ASK. Says nothing about the path.
* ``not_probed`` — the run stopped before reaching this block (budget). Says
                   nothing about anything, and must never render as "no REST
                   path exists": that is the one sentence this run could tell
                   that would be both confident and false.

Pure planner + driver. The probe is INJECTED, so the guards drive whole runs
with no appliance, no network and no Flask.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from . import api_matrix, cli_coverage

#: Verdicts a candidate row can carry. The first three come straight from
#: ``rediscovery`` (never re-spelled here — a second vocabulary for the same
#: answer is how two pages start disagreeing about one device).
SERVED = "ok"
ABSENT = "absent"
ERROR = "error"
#: Ours, and deliberately outside the device's vocabulary: it describes the
#: RUN, not the appliance.
NOT_PROBED = "not_probed"

#: Ceiling on GETs one run may fire at one appliance. A dump with 84 CLI-only
#: blocks × up to 8 candidates each is 672 requests; that is not a scan, that is
#: a load test. The budget is REPORTED, never silently applied — a truncated run
#: that looks complete would say "the device serves nothing for these blocks",
#: which is the inverse of what a budget means.
DEFAULT_BUDGET = 240


@dataclass
class Candidate:
    """One derived REST path and what the device said about it."""

    urn: str
    verdict: str = NOT_PROBED
    rows: int = 0
    detail: str = ""

    @property
    def served(self) -> bool:
        return self.verdict == SERVED

    def to_dict(self) -> dict[str, Any]:
        return {"urn": self.urn, "verdict": self.verdict, "rows": self.rows,
                "detail": self.detail[:200], "served": self.served}


@dataclass
class Finding:
    """One CLI-only block, its candidates, and the outcome of asking about them."""

    path: str
    name: str
    configured: bool = False
    instances: int = 0
    settings: int = 0
    candidates: list[Candidate] = field(default_factory=list)
    #: Why this block has no candidates at all (too short to derive a path).
    underivable: str = ""
    #: The catalog already has this name, pointing at a DIFFERENT urn. Shown
    #: before the run so the operator renames rather than discovering the
    #: collision in a flash message after 200 GETs.
    name_taken: str = ""
    #: The served urn is ALREADY in the catalog under another name — the block
    #: is covered and the diff's bucketing is what is stale, not the catalog.
    urn_known: str = ""

    @property
    def served(self) -> Candidate | None:
        for c in self.candidates:
            if c.served:
                return c
        return None

    @property
    def probed(self) -> int:
        return sum(1 for c in self.candidates if c.verdict != NOT_PROBED)

    @property
    def status(self) -> str:
        """The block's own verdict — derived from its candidates, never stored.

        Ordered so the weakest claim wins: one served path makes the block
        ``ok``; otherwise an unfinished run is ``not_probed`` (we do not know),
        an asking failure is ``error`` (we could not ask), and only when every
        candidate was tried AND answered does it become ``absent`` (the device
        says no).
        """
        if self.underivable:
            return "underivable"
        if self.served:
            return SERVED
        if any(c.verdict == NOT_PROBED for c in self.candidates):
            return NOT_PROBED
        if any(c.verdict == ERROR for c in self.candidates):
            return ERROR
        return ABSENT if self.candidates else "underivable"

    @property
    def registerable(self) -> bool:
        """May this row be offered for registration?

        Three conditions, all necessary: the device served a path, the catalog
        does not already know that path, and the name it would take is free.
        """
        return bool(self.served and not self.urn_known and not self.name_taken)

    def to_dict(self) -> dict[str, Any]:
        served = self.served
        return {
            "path": self.path, "name": self.name, "configured": self.configured,
            "instances": self.instances, "settings": self.settings,
            "candidates": [c.to_dict() for c in self.candidates],
            "underivable": self.underivable, "name_taken": self.name_taken,
            "urn_known": self.urn_known, "status": self.status,
            "probed": self.probed, "registerable": self.registerable,
            "served_urn": served.urn if served else "",
            "served_rows": served.rows if served else 0,
        }


def catalog_index(product: str) -> tuple[dict, dict]:
    """``({name: urn}, {normalised urn: name})`` for one product's live catalog.

    Read through the SAME loader call ``cli_coverage._catalog`` uses for this
    product — ``load_registry`` / ``load_adc_registry``, both DB-first with the
    YAML as seed. A second reader here could disagree with the diff about what
    the catalog contains, and the disagreement would show up as a run offering
    to register something that is already registered.
    """
    from ..registry import loader

    reg = (loader.load_adc_registry() if product == "fortiadc"
           else loader.load_registry() if product == "fortiweb" else {})
    by_name: dict[str, str] = {}
    by_urn: dict[str, str] = {}
    for name in sorted(reg):
        urn = reg[name] or ""
        if not name or not urn:
            continue
        by_name.setdefault(name, urn)
        by_urn.setdefault(_norm(urn), name)
    return by_name, by_urn


def _norm(urn: str) -> str:
    """Compare urns the way the catalog stores them: no query, no trailing slash."""
    return (urn or "").split("?")[0].rstrip("/")


def plan(product: str, diff: dict, *, configured_only: bool = False,
         by_name: dict | None = None, by_urn: dict | None = None,
         limit: int | None = None) -> list[Finding]:
    """The rows a run WOULD probe, with zero device contact.

    Built from the ``cli_only`` bucket of a diff the page already computed — so
    the run and the coverage table underneath it can never disagree about which
    blocks are missing.

    ``configured_only`` keeps only blocks that hold configuration on this box.
    It defaults to **False**: an empty table is still a catalog gap, and
    defaulting to the smaller set would quietly redefine the question from
    "what is missing" to "what is missing AND in use here".
    """
    if by_name is None or by_urn is None:
        idx_name, idx_urn = catalog_index(product)
        by_name = by_name if by_name is not None else idx_name
        by_urn = by_urn if by_urn is not None else idx_urn

    rows = list(diff.get(cli_coverage.BUCKET_CLI_ONLY) or [])
    if configured_only:
        rows = [r for r in rows if r.get("configured")]
    # Configured blocks first: a table carrying 69 rows is a bigger gap than one
    # nobody has filled in, and with a budget the order decides what gets asked.
    rows.sort(key=lambda r: (not r.get("configured"), r.get("path") or ""))
    if limit is not None:
        rows = rows[:limit]

    out: list[Finding] = []
    for rec in rows:
        path = rec.get("path") or ""
        name = cli_coverage.catalog_name_for(path)
        urns = cli_coverage.candidate_urns(product, path)
        f = Finding(
            path=path, name=name,
            configured=bool(rec.get("configured")),
            instances=int(rec.get("instances") or 0),
            settings=len(rec.get("settings") or ()),
            candidates=[Candidate(u) for u in urns],
            underivable=("" if urns else
                         "no REST path can be derived from a one-word block"),
        )
        taken = by_name.get(name)
        if taken:
            f.name_taken = taken
        out.append(f)
    return out


def run(findings: Iterable[Finding], probe: Callable[[str], tuple],
        *, budget: int = DEFAULT_BUDGET,
        by_urn: dict | None = None,
        on_progress: Callable[[int, int, int, str], None] | None = None
        ) -> dict[str, Any]:
    """Probe each finding's candidates until one is served, or the budget ends.

    ``probe(urn) -> (rows, verdict, detail)`` — the shape
    :func:`rediscovery.probe_endpoint` already returns, bound to one appliance
    by the caller.

    STOP AT THE FIRST SERVED PATH. The candidates are the same collection
    spelled the handful of ways FortiWeb spells it; once the device has served
    one, asking for the rest costs GETs to learn nothing. What that costs is
    honesty about the others, so :attr:`Finding.probed` records how many were
    actually asked and the template never prints an unasked candidate as absent.

    A probe that RAISES sinks that candidate, never the run: one unreachable
    collection must not cost the other 83 findings their answer.

    ``on_progress(index, total, spent, path)`` is called BEFORE each block is
    asked about, never after: a run that dies mid-GET then leaves the last
    message naming the block it was asking about rather than the one it had
    already finished. It is also where the job worker puts its cancellation
    checkpoint, so raising out of it is a supported way to stop — the blocks
    after it keep their NOT_PROBED verdict, which is the honest state.
    """
    findings = list(findings)
    by_urn = {} if by_urn is None else by_urn
    spent = 0
    _total = len(findings)
    for _idx, f in enumerate(findings, 1):
        if on_progress is not None:
            on_progress(_idx, _total, spent, f.path)
        if f.underivable:
            continue
        for cand in f.candidates:
            if spent >= budget:
                break                      # leaves NOT_PROBED — the honest state
            spent += 1
            try:
                rows, verdict, detail = probe(cand.urn)
            except Exception as exc:       # noqa: BLE001 — one candidate, not the run
                cand.verdict, cand.rows = ERROR, 0
                cand.detail = "%s: %s" % (type(exc).__name__, exc)
                continue
            cand.verdict = verdict or ERROR
            cand.rows = len(rows or ())
            cand.detail = detail or ""
            if cand.served:
                known = by_urn.get(_norm(cand.urn))
                if known:
                    f.urn_known = known
                break
        if spent >= budget:
            break

    return {
        "findings": findings,
        "spent": spent,
        "budget": budget,
        # Stated, never implied. ``exhausted`` is why rows are NOT_PROBED.
        "exhausted": spent >= budget,
        "not_probed": sum(1 for f in findings if f.status == NOT_PROBED),
        "served": sum(1 for f in findings if f.status == SERVED),
        "absent": sum(1 for f in findings if f.status == ABSENT),
        "errors": sum(1 for f in findings if f.status == ERROR),
        "registerable": sum(1 for f in findings if f.registerable),
        "name_taken": sum(1 for f in findings if f.name_taken),
        "urn_known": sum(1 for f in findings if f.urn_known),
    }


def summary_line(result: dict) -> str:
    """One sentence an audit row and a flash message can both carry."""
    bits = ["%d served" % result.get("served", 0),
            "%d absent" % result.get("absent", 0)]
    if result.get("errors"):
        bits.append("%d could not be asked" % result["errors"])
    if result.get("not_probed"):
        bits.append("%d not reached (budget %d)"
                    % (result["not_probed"], result.get("budget", 0)))
    return "%d GETs: %s" % (result.get("spent", 0), ", ".join(bits))


# ---------------------------------------------------------------------------
# which firmware these answers describe
# ---------------------------------------------------------------------------
# A run has TWO sources and they are not necessarily the same box: the
# candidates are derived from a CLI dump (the evidence the coverage section
# chose) and the verdicts come from whatever appliance is asked. Let those
# diverge and every ``absent`` is literally true and completely misleading —
# "that device does not have it" read as "that path does not exist". The
# firmware LINE is the sharper half of the divergence: two 7.6 boxes answer
# about the same API surface, a 7.6 dump and an 8.0 device do not.
#
# So the running version is read off the device and STORED — through
# ``firmware_probe.refresh``, which is the one author of that write and the one
# thing that stamps ``firmware_checked_at`` with it. A version persisted
# without its attestation is a row that cannot say whether it was ever checked.
#
# THIS WARNS. IT DOES NOT GATE. The vocabulary below contains ``unknown`` for
# "we could not establish it", so a gate built on it would refuse a legitimate
# run because OUR read failed — the same reason the upgrade advisory advises
# and never refuses. There is a guard that fails if anyone turns it into a
# gate.
SAME_LINE = "same"
OTHER_LINE = "different"
#: Deliberately outside the two answers above: it describes OUR read, not the
#: device. Folding it into either one would state a comparison nobody made.
UNKNOWN_LINE = "unknown"


def detect_version(appliance, *, probe=None) -> dict:
    """Read the running firmware off *appliance* and persist it. NEVER raises.

    The write is delegated to :func:`app.services.firmware_probe.refresh`
    whole — version, model, hostname, serial and the ``firmware_checked_at``
    attestation — rather than assigning ``appliance.firmware`` here, which is
    how ``rediscovery.apply_inventory`` came to store a version with no
    timestamp saying when it was observed.

    ``probe`` is injected so the guards can drive this with no device, no
    network and no Flask.
    """
    if probe is None:
        from . import firmware_probe
        probe = firmware_probe.refresh
    try:
        res = probe(appliance)
    except Exception as exc:  # noqa: BLE001 — a version read must not 500 a run
        res = {"ok": False, "error": "unreachable",
               "detail": "%s: %s" % (type(exc).__name__, exc)}
    name = getattr(appliance, "name", "") or "?"
    out = {"checked": bool(res.get("ok")), "firmware": "", "line": "",
           "checked_at": "", "changed": False, "previous": "",
           "error": "", "detail": "", "device": name}
    if not res.get("ok"):
        out["error"] = res.get("error") or "unreadable"
        out["detail"] = str(res.get("detail") or "")[:200]
        return out
    out["firmware"] = res.get("firmware") or ""
    out["line"] = api_matrix.firmware_line(out["firmware"])
    out["checked_at"] = res.get("checked_at") or ""
    out["changed"] = bool(res.get("changed"))
    out["previous"] = res.get("previous") or ""
    return out


def version_check(appliance, evidence=None, *, probe=None) -> dict:
    """:func:`detect_version` + the comparison against the dump's firmware line.

    Returns the detection dict extended with ``verdict`` (:data:`SAME_LINE` /
    :data:`OTHER_LINE` / :data:`UNKNOWN_LINE`), a ``reason`` written for the
    operator, and ``same_device`` — whether the dump came off the very box
    being asked, compared by **id**, because two appliances can carry the same
    name and a stale name is not a device.
    """
    ev = evidence or {}
    out = detect_version(appliance, probe=probe)
    ev_line = str(ev.get("line") or "").strip()
    ev_id = ev.get("appliance_id")
    out.update({
        "evidence_line": ev_line,
        "evidence_appliance": ev.get("appliance") or "",
        "evidence_firmware": ev.get("firmware") or "",
        "evidence_captured": ev.get("created_at") or "",
        # None, not False: "there is no evidence" is not "a different device".
        "same_device": (bool(ev_id is not None
                             and ev_id == getattr(appliance, "id", None))
                        if ev_id is not None else None),
        "verdict": UNKNOWN_LINE,
        "reason": "",
    })
    name = out["device"]
    if not out["checked"]:
        out["reason"] = (
            "the running version could not be read off %s (%s), so nothing "
            "here establishes which firmware these answers describe"
            % (name, out["error"]))
        return out
    if not out["line"]:
        out["reason"] = (
            "%s answered with a version string no firmware line could be read "
            "from (%r)" % (name, out["firmware"][:60]))
        return out
    if not ev_line:
        out["reason"] = (
            "%s is running %s, but the dump does not record which firmware "
            "line it was captured on, so the two cannot be compared"
            % (name, out["line"]))
        return out
    if ev_line == out["line"]:
        out["verdict"] = SAME_LINE
        out["reason"] = ("the dump was captured on %s and %s is running %s"
                         % (ev_line, name, out["line"]))
        return out
    out["verdict"] = OTHER_LINE
    out["reason"] = (
        "the dump was captured on %s and %s is running %s: a block that is "
        "missing on one line is not a block that does not exist, so read every "
        "verdict below as an answer about %s"
        % (ev_line, name, out["line"], out["line"]))
    return out


__all__ = ["SERVED", "ABSENT", "ERROR", "NOT_PROBED", "DEFAULT_BUDGET",
           "SAME_LINE", "OTHER_LINE", "UNKNOWN_LINE",
           "Candidate", "Finding", "catalog_index", "plan", "run",
           "detect_version", "version_check", "summary_line"]
