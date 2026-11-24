"""Scout Advisory — turns the harvested upgrade prose into VERDICTS.

The Release-Notes corpus already answers "what bugs do I gain and inherit".
It does not answer the question that actually sinks an upgrade window, which is
the one a minor release hides best:

    FortiWeb 8.0.7's *Supported upgrade paths* says that anything at 7.6.1 or
    lower must land on 7.6.2 first, and that 7.6.2 expands the partition and
    needs 1.5 GB free on the log disk. Both sentences sit in the middle of a
    13 000-character page for a MAINTENANCE release, which is exactly the page
    an operator skims.

So this module reads the prose SATOM already holds and emits findings: a
severity, a statement of what the operator must do, and the VERBATIM sentence it
came from. The verbatim evidence is not decoration — a rule that paraphrases a
vendor's prerequisite and gets it slightly wrong is worse than no rule, because
it is believed.

Three rules of the house, carried over from ``scout_ladder``:

1. **Absence is never innocence.** If the crossed versions are not in the corpus,
   the report says UNKNOWN and names what is missing. It never renders a clean
   advisory over data it does not have.
2. **The criteria are not editable.** :data:`RULES` is the single author of every
   verdict, and :func:`rules_digest` seals WHICH rules ran into the report, so an
   advisory read six months from now is reproducible. An editable threshold makes
   a second author of an archived verdict.
3. **A catch-all beats a complete list.** :func:`_rule_marked_caution` surfaces
   every block Fortinet themselves marked *Caution* / *Warning*, so prose this
   module has never seen still reaches the operator — just without a tailored
   verdict.

Pure module: no Flask, no DB, no network. It reads ``ReleaseSection`` rows.
"""
from __future__ import annotations

import hashlib
import inspect
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .release_notes import (
    SECTION_LABEL, UPGRADE_SECTIONS, ReleaseSection, version_key, version_tuple,
)

#: Severity vocabulary, most severe first. ``blocker`` means "this upgrade will
#: fail, or damage something, unless you act first" — not "important".
SEVERITIES: tuple[str, ...] = ("blocker", "caution", "note")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

#: Within a severity, the order findings are READ in. Declared, because the
#: fallback is the rule id's spelling: "free-space" sorts above
#: "mandatory-hop", so a disk prerequisite led the panel and the verdict that
#: says the upgrade is not a supported path sat underneath it. Anything not
#: listed sorts after everything listed, in a stable order.
RULE_ORDER: tuple[str, ...] = (
    "target-prohibition",        # there is no window at all
    "mandatory-hop",             # you cannot get there from here
    "repartition",               # …and here is the other way you cannot
    "downgrade-discouraged",
    "downgrade-data-loss",
    "free-space",                # then the things to do before the window
    "backup-not-restorable",
    "downgrade-admin-hash",
    "vm-license",
    "ha-unsupported",
    "ha-automatic",              # then what to expect during it
    "stated-path",
    "vendor-marked",             # then everything we have no verdict for
)
_RULE_RANK = {r: i for i, r in enumerate(RULE_ORDER)}

_VER = r"\d+(?:\.\d+){1,3}"


# --------------------------------------------------------------------------- #
#  Data model                                                                   #
# --------------------------------------------------------------------------- #
@dataclass
class Block:
    """One paragraph of harvested prose, with its provenance intact."""

    version: str
    section: str
    text: str
    source_url: str
    index: int          # position in the FLAT block list (see Ctx.next_block)


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    detail: str         # what the operator must DO, in our words
    evidence: str       # the vendor's words, verbatim
    version: str
    section: str
    source_url: str
    #: Structured facts a rule extracted (e.g. ``{"hop": "7.6.2"}``). Consumers
    #: read THIS, never the prose of ``detail`` — re-parsing our own sentence to
    #: recover a value the rule already had is how a guard ends up matching its
    #: own wording instead of the behaviour.
    data: dict = field(default_factory=dict)


#: Why a (version, section) is missing. The two are not the same problem: one is
#: a version nobody ever harvested, the other is a corpus that predates the
#: section existing — and only the second is fixed by pressing Scan again.
GAP_ABSENT = "the version is not in the corpus at all"
GAP_STALE = "harvested before this section was collected — rescan this version"


@dataclass
class Gap:
    """A (version, section) the advisory needed and the corpus does not have."""

    version: str
    section: str
    reason: str = GAP_ABSENT


@dataclass
class Advisory:
    current: str
    target: str
    is_upgrade: bool
    verdict: str                                     # blocker|caution|clear|unknown
    findings: list[Finding] = field(default_factory=list)
    path: list[str] = field(default_factory=list)    # required hop sequence
    gaps: list[Gap] = field(default_factory=list)
    read: list[Gap] = field(default_factory=list)    # what WAS read (the coverage)
    rules_digest: str = ""
    generated_at: str = ""


@dataclass
class Ctx:
    current: str
    target: str
    is_upgrade: bool
    blocks: list[Block]

    @property
    def cur_t(self) -> tuple[int, ...]:
        return version_tuple(self.current)

    @property
    def tgt_t(self) -> tuple[int, ...]:
        return version_tuple(self.target)

    def crossed(self, v: str) -> bool:
        """True iff ``v`` lies in the half-open range the move traverses."""
        t = version_tuple(v)
        lo, hi = (self.cur_t, self.tgt_t) if self.is_upgrade else (self.tgt_t, self.cur_t)
        return lo < t <= hi

    def of(self, *sections: str) -> list[Block]:
        return [b for b in self.blocks if b.section in sections]

    def prev_block(self, b: Block) -> Block | None:
        """The block immediately before ``b``, within its own section.

        Same flat-list indexing as :meth:`next_block`, and for the same reason.
        Used for the HEADING a vendor puts above a paragraph — read for a title
        only, never as a trigger: measured against the live corpus, "a short
        line followed by a long one" matches 28-30 times per version, so a
        detector built on it would bury the panel it is meant to sharpen."""
        prv = b.index - 1
        if prv < 0:
            return None
        other = self.blocks[prv]
        if other.version != b.version or other.section != b.section:
            return None
        return other

    def next_block(self, b: Block) -> Block | None:
        """The block immediately after ``b``, within its own section.

        Indexed by POSITION IN THE FLAT LIST, not by a per-section counter. Two
        rows for the same ``(version, section)`` — a corpus merged badly, or a
        test that appends one — gave every block a duplicate index, and this
        lookup then returned a paragraph from the OTHER row. A Caution attached
        to somebody else's sentence is the worst failure available to a rule
        whose whole contract is that the evidence is verbatim and belongs to it.
        """
        nxt = b.index + 1
        if nxt >= len(self.blocks):
            return None
        other = self.blocks[nxt]
        if other.version != b.version or other.section != b.section:
            return None
        return other


def _finding(rule, severity, title, detail, b: Block) -> Finding:
    return Finding(rule=rule, severity=severity, title=title, detail=detail,
                   evidence=b.text, version=b.version, section=b.section,
                   source_url=b.source_url)


# --------------------------------------------------------------------------- #
#  Rules. Each takes the Ctx and returns findings. Keep them small and literal. #
# --------------------------------------------------------------------------- #
_RE_HOP = re.compile(
    r"upgrading from a version that is\s+(" + _VER + r")\s+or lower.{0,120}?"
    r"upgrade to (?:version\s+)?(" + _VER + r")\s+before", re.I | re.S)


def _rule_mandatory_hop(ctx: Ctx) -> list[Finding]:
    """A stated floor below which a direct upgrade is not supported.

    THE rule this module exists for. On 8.0.7 the sentence is 'If you are
    upgrading from a version that is 7.6.1 or lower, then you will need to
    upgrade to version 7.6.2 before proceeding' — a hard two-step, announced in
    a maintenance release's notes."""
    out = []
    if not ctx.is_upgrade:
        return out
    for b in ctx.of("upgrading_from"):
        m = _RE_HOP.search(b.text)
        if not m:
            continue
        floor, hop = m.group(1), m.group(2)
        if ctx.cur_t > version_tuple(floor):
            continue
        f = _finding(
            "mandatory-hop", "blocker",
            f"{ctx.target} cannot be installed directly from {ctx.current}",
            f"{ctx.current} is at or below {floor}, so the supported route is "
            f"{ctx.current} → {hop} → {ctx.target}. Plan two maintenance windows, "
            f"not one; going straight to {ctx.target} is not a supported path.",
            b)
        f.data = {"floor": floor, "hop": hop}
        out.append(f)
    return out


_RE_PATH = re.compile(r"(" + _VER + r"(?:\s*(?:→|->|&rarr;)\s*" + _VER + r"){1,5})")


def _rule_stated_path(ctx: Ctx) -> list[Finding]:
    """An explicit hop chain the vendor drew (``7.2.1 → 7.6.2 → 8.0.7``)."""
    out = []
    for b in ctx.of("upgrading_from"):
        m = _RE_PATH.search(b.text)
        if m and ctx.is_upgrade:
            out.append(_finding(
                "stated-path", "note", "The vendor draws an example upgrade path",
                "Read it as the SHAPE of the route, not as your route: the "
                "endpoints are Fortinet's example, the intermediate hop is the "
                "part that binds.", b))
    return out


_RE_SPACE = re.compile(
    r"at least\s+([\d.]+)\s*(TB|GB|MB)\s+of free\s+(?:disk\s+)?space", re.I)
_RE_PARTITION_VER = re.compile(
    r"[Vv]ersion\s+(" + _VER + r")\s+introduces an expanded partition", re.I)


def _rule_free_space(ctx: Ctx) -> list[Finding]:
    """A disk prerequisite stated as a number.

    Gated on the version that INTRODUCES the expanded partition when the prose
    names one: a prerequisite that belongs to a hop you are not crossing is
    noise, and noise is what gets this whole panel ignored. When the prose does
    NOT name a version, the finding is raised anyway — an ungated prerequisite
    is a cheap check, an unmet one is a failed upgrade."""
    out = []
    if not ctx.is_upgrade:
        return out
    for b in ctx.of(*UPGRADE_SECTIONS):
        m = _RE_SPACE.search(b.text)
        if not m:
            continue
        mv = _RE_PARTITION_VER.search(b.text)
        if mv and not ctx.crossed(mv.group(1)):
            continue
        amount = f"{m.group(1)} {m.group(2).upper()}"
        where = f" (introduced in {mv.group(1)})" if mv else ""
        out.append(_finding(
            "free-space", "blocker", f"Free-space prerequisite: {amount}",
            f"Verify at least {amount} of free space BEFORE the window{where}. "
            f"This is checked by the upgrade, not by you — an appliance that is "
            f"short simply fails partway.", b))
    return out


_RE_REPARTITION = re.compile(
    r"previous to\s+(" + _VER + r").{0,80}?you must first resize", re.I | re.S)


def _rule_repartition(ctx: Ctx) -> list[Finding]:
    """The disk repartition floor (pre-5.5), which needs a special build."""
    out = []
    if not ctx.is_upgrade:
        return out
    for b in ctx.of("repartitioning"):
        m = _RE_REPARTITION.search(b.text)
        if m and ctx.cur_t < version_tuple(m.group(1)):
            out.append(_finding(
                "repartition", "blocker",
                "The OS disk must be repartitioned before this upgrade",
                f"{ctx.current} predates {m.group(1)}: the upgrade needs a special "
                f"repartitioning build from Fortinet Support first, and on Xen / "
                f"Hyper-V / KVM it cannot be installed at all — those redeploy.", b))
    return out


_RE_HA_SUPPORT = re.compile(
    r"HA cluster is running.{0,80}?contact Fortinet Technical Support", re.I | re.S)
_RE_HA_AUTO = re.compile(
    r"upgrade the active appliance.{0,120}?automatically upgrades", re.I | re.S)


def _rule_ha(ctx: Ctx) -> list[Finding]:
    """How the cluster behaves during the window — good news included.

    An operator who does not know the active appliance drags the standby with it
    plans a manual second upgrade and a second outage."""
    out = []
    if not ctx.is_upgrade:
        return out
    for b in ctx.of("ha_upgrade"):
        if _RE_HA_SUPPORT.search(b.text):
            out.append(_finding(
                "ha-unsupported", "caution",
                "Old HA clusters are not upgraded unattended",
                "On the firmware generation named here, Fortinet ask you to call "
                "Support rather than upgrade the cluster yourself.", b))
        elif _RE_HA_AUTO.search(b.text):
            out.append(_finding(
                "ha-automatic", "note",
                "The active appliance upgrades the standby for you",
                "Upgrade the ACTIVE member only. Do not schedule a second window "
                "for the standby, and do not upgrade it by hand.", b))
    return out


_RE_DOWNGRADE_NO = re.compile(
    r"(?:do not|don't|does not)\s+recommend performing a downgrade", re.I)
_RE_DOWNGRADE_LOSS = re.compile(
    r"(?:will be|is) lost if you downgrade to versions lower than\s+(" + _VER + r")", re.I)
_RE_DOWNGRADE_HASH = re.compile(
    r"password hash.{0,120}?(?:sha1 to sha256|convert password hash)", re.I | re.S)


def _rule_downgrade(ctx: Ctx) -> list[Finding]:
    """Everything that only matters when the move goes DOWN.

    The advisor is symmetric on purpose: a rollback is the plan you execute when
    the window has already gone wrong, which is the worst moment to discover that
    the ML database does not survive it."""
    out = []
    if ctx.is_upgrade:
        return out
    for b in ctx.of("downgrading"):
        if _RE_DOWNGRADE_NO.search(b.text):
            out.append(_finding(
                "downgrade-discouraged", "blocker",
                "Fortinet do not support this as a routine operation",
                "Open a Support case BEFORE rolling back. Uploading a lower image "
                "counts as a downgrade even if you never boot it.", b))
        m = _RE_DOWNGRADE_LOSS.search(b.text)
        if m and ctx.tgt_t < version_tuple(m.group(1)):
            out.append(_finding(
                "downgrade-data-loss", "blocker",
                f"Data is destroyed below {m.group(1)}",
                f"Rolling back to {ctx.target} crosses {m.group(1)} — the data named "
                f"here does not come back when you upgrade again. Export it first "
                f"or accept losing it.", b))
        if _RE_DOWNGRADE_HASH.search(b.text):
            out.append(_finding(
                "downgrade-admin-hash", "caution",
                "Administrators may not be able to log in after the rollback",
                "Have console access ready: the admin password hash changed, and "
                "a rollback across that change can lock every admin account out of "
                "the GUI and SSH.", b))
    return out


_RE_NOT_RESTORABLE = re.compile(r"backup.{0,40}?no longer be restorable", re.I | re.S)
_RE_PRIOR_TO = re.compile(r"(?:prior to|previous to|earlier than)\s+(" + _VER + r")", re.I)


def _rule_backup_not_restorable(ctx: Ctx) -> list[Finding]:
    """A backup taken before the window that will not restore after it.

    This one inverts the usual advice — 'take a backup first' is the reflex, and
    here the backup is precisely what stops being useful."""
    out = []
    if not ctx.is_upgrade:
        return out
    for b in ctx.of("upgrade_notes"):
        if not _RE_NOT_RESTORABLE.search(b.text):
            continue
        m = _RE_PRIOR_TO.search(b.text)
        if m and ctx.cur_t >= version_tuple(m.group(1)):
            continue
        out.append(_finding(
            "backup-not-restorable", "caution",
            "Your pre-upgrade backup may not restore afterwards",
            "Take a FRESH backup immediately after the upgrade — the rollback plan "
            "you are holding does not survive this hop.", b))
    return out


_RE_VM_UUID = re.compile(
    r"previous to\s+(" + _VER + r").{0,120}?universal unique identifier", re.I | re.S)


def _rule_vm_license(ctx: Ctx) -> list[Finding]:
    out = []
    if not ctx.is_upgrade:
        return out
    for b in ctx.of("vm_license"):
        m = _RE_VM_UUID.search(b.text)
        if m and ctx.cur_t < version_tuple(m.group(1)):
            out.append(_finding(
                "vm-license", "caution",
                "The VM licence will be rejected the first time",
                "Expect the FDN to call a valid licence invalid. Wait 90 minutes "
                "and upload it again before escalating.", b))
    return out


_MARKS = {"caution": "caution", "warning": "caution", "important": "caution",
          "note": "note"}

#: Rules whose SCOPE is the destination, not the span below it.
#:
#: Every other rule in this module answers "does the move start low enough for
#: this to bite?" — they compare ``ctx.cur_t`` against a floor the vendor wrote
#: down. A whole class of hazard has no floor: *"do not upgrade to 8.0.7"* is
#: true from 8.0.6 and true from 7.2.1 alike, and a motor that can only express
#: floors answers "nothing found" for every single origin. That is exactly what
#: 8.0.7 did, with the sentence sitting in the corpus the whole time.
TARGET_SCOPED: frozenset = frozenset({"target-prohibition"})

#: An explicit vendor instruction NOT to make a move, naming the version. Kept
#: narrow on purpose: this promotes a finding to *blocker*, so it matches an
#: imperative aimed at upgrading/installing a NAMED version and nothing looser.
#: "Do not use a lower patch" and "we do not recommend…" are deliberately out —
#: the first names no version, the second is a recommendation and already lands
#: as a caution through the catch-all.
_RE_PROHIBITION = re.compile(
    r"(?:do not|don't|must not|should not)\s+(?:upgrade|install|update)"
    r"[^.]{0,60}?\bto\s+(?:FortiWeb[\s-]*)?(" + _VER + r")"
    r"|not supported to upgrade to\s+(?:FortiWeb[\s-]*)?(" + _VER + r")", re.I)

#: A vendor heading: short, unpunctuated, more than one word. Read ONLY to title
#: a finding whose trigger is already the prose below it.
_RE_HEADINGISH = re.compile(r"^(?!.*[.!?]$)(?=(?:\S+\s+){1,}\S)[^\n]{4,79}$")


def _condition_label(ctx: Ctx, b: Block) -> str:
    """The vendor's own heading above ``b``, when there is one."""
    prev = ctx.prev_block(b)
    if prev and _RE_HEADINGISH.match(prev.text.strip()):
        return prev.text.strip()
    return ""


def _rule_target_prohibition(ctx: Ctx) -> list[Finding]:
    """The vendor says *do not make this move*, and says it about the TARGET.

    The rule this module was missing. FortiWeb 8.0.7's *Upgrade notes* carry
    'If you are running FortiWeb in a VM environment and the total number of
    configured server policies exceeds 20, do not upgrade to FortiWeb 8.0.7 at
    this time' — unmarked prose, no floor, and therefore invisible both to the
    catch-all (which needs a vendor mark) and to every tailored rule (which
    needs a floor).

    CONDITIONAL BY NATURE, and the finding says so rather than pretending
    otherwise: the condition is the vendor's, it is quoted verbatim, and the
    title carries their own heading for it. Emitting this as a note because it
    might not apply would bury the words 'do not upgrade' under four other
    notes; emitting it as a blocker that NAMES its condition is a gate the
    operator clears in one glance."""
    out = []
    if not ctx.is_upgrade:
        return out
    for b in ctx.of("upgrade_notes", "upgrading_from", "ha_upgrade"):
        m = _RE_PROHIBITION.search(b.text)
        if not m:
            continue
        named = m.group(1) or m.group(2)
        # THE DESTINATION, not merely a version the span steps over. Measured:
        # gating on ``crossed`` made 7.2.1 -> 8.0.7 emit a blocker about a
        # FortiWeb 100D incompatibility with 7.6.0 — a release that move never
        # installs, because its supported route lands on 7.6.2. A prohibition
        # is an instruction not to RUN a version, so the only version it can
        # bind is the one being installed.
        #
        # KNOWN LIMIT, stated rather than hidden: a prohibition attached to a
        # mandatory HOP (7.6.2 here) is not raised, because the hops are derived
        # from the findings and so do not exist yet when the rules run. The
        # hop's own advisory shows it; a second pass here would have to re-enter
        # the rule set, and guessing the route instead is how the 7.6.0 false
        # blocker above happened.
        if version_tuple(named) != ctx.tgt_t:
            continue
        if _floor_excludes(b.text, ctx):
            continue
        label = _condition_label(ctx, b)
        f = _finding(
            "target-prohibition", "blocker",
            f"Fortinet say do not upgrade to {named}"
            + (f" — {label}" if label else ""),
            f"This is not a prerequisite you can satisfy: the vendor publishes "
            f"an instruction not to install {named} at all. It is CONDITIONAL — "
            f"the condition is in their words below"
            + (f", under their own heading \u201c{label}\u201d" if label else "")
            + f". Confirm your appliance does not meet it before booking the "
            f"window; if it does, there is no window until Fortinet withdraw "
            f"this.", b)
        f.data = {"scope": "target", "named": named, "condition": label}
        out.append(f)
    return out


def _headline(mark: str, text: str, section: str, limit: int = 88) -> str:
    """A title taken from the block's OWN first sentence.

    Titling these by their mark and section produced five findings called
    "Note in Upgrading from previous releases", stacked, each with the same
    sentence of ours underneath. A list where every row has the same name is a
    list nobody reads — and the one row that mattered was in it."""
    word = mark.strip().rstrip(":").title() or "Note"
    body = (text or "").strip()
    # A MadCap admonition carries its own mark INSIDE the body ("Note : This
    # issue has been resolved…"), and the body is the evidence, so it must stay
    # verbatim. Strip the mark for the TITLE only — otherwise the first
    # "sentence" is the word "Note :" and every such row is called "Note: Note :".
    body = _RE_MARK_EMBEDDED.sub("", body, count=1)
    first = re.split(r"(?<=[.:;])\s", body, maxsplit=1)[0].strip()
    if len(first) > limit:
        first = first[:limit].rsplit(" ", 1)[0] + "…"
    if not first:
        return f"{word} in {SECTION_LABEL.get(section, section)}"
    return f"{word}: {first}"


#: A mark word sitting ALONE on its line — the markdown renderer's shape, where
#: the admonition body is the next block.
_RE_MARK_PURE = re.compile(r"^(caution|warning|important|note)\s*:?$", re.I)

#: The SAME admonition as MadCap renders it: the mark is glued to the sentence
#: ("Note : This issue has been resolved…"). Measured over the live corpus:
#: pure-mark lines number 0 in every FortiWeb version from 7.6.5 to 8.0.6 and 18
#: in 8.0.7 — because Fortinet changed renderers, not because eleven releases
#: shipped without a single caveat. A catch-all that only knows one of the two
#: shapes is not a catch-all; it is a catch-all for the current renderer, and it
#: goes quiet the day that changes without anything failing.
_RE_MARK_EMBEDDED = re.compile(
    r"^(caution|warning|important|note)\s*[:\-\u2013\u2014]\s*(?=\S)", re.I)


def admonitions(ctx: Ctx, *sections: str) -> list[tuple[str, Block]]:
    """Every ``(mark word, body block)`` the VENDOR marked, in either renderer.

    The mark comes back AS FORTINET WROTE IT — ``Warning``, not the ``caution``
    severity it maps to. Returning the severity instead reprinted a vendor
    *Warning* as "Caution: …" in the panel: a classification of ours, wearing
    the typography of a quotation. Callers map it through :data:`_MARKS` when
    they need a severity.

    The single author of that notion. The catch-all rule consumes it and so does
    the coverage guard, on purpose: a corpus the catch-all cannot read is the
    defect, so the thing that measures readability has to be the thing that
    reads. Two authors for this would let the guard stay green over a catch-all
    that had gone blind — which is the exact failure it exists to catch."""
    out: list[tuple[str, Block]] = []
    for b in (ctx.of(*sections) if sections else ctx.blocks):
        text = b.text.strip()
        m = _RE_MARK_PURE.match(text)
        if m:
            nxt = ctx.next_block(b)
            if nxt is None or not nxt.text.strip():
                continue
            out.append((m.group(1), nxt))
            continue
        m = _RE_MARK_EMBEDDED.match(text)
        if m and len(text) > len(m.group(0)) + 20:
            out.append((m.group(1), b))
    return out


def admonition_coverage(sections: list[ReleaseSection], *,
                        product: str = "fortiweb") -> dict[str, int]:
    """Per-version count of vendor-marked blocks the catch-all can actually see.

    A zero here is never "that release had nothing to warn about": Fortinet mark
    the upgrade pages of every FortiWeb release. A zero means the corpus is
    being read by a parser that no longer matches the renderer."""
    rows = [s for s in sections
            if s.product == product and s.section in UPGRADE_SECTIONS]
    out: dict[str, int] = {}
    for v in sorted({s.version for s in rows}, key=version_key):
        ctx = Ctx(current=v, target=v, is_upgrade=True,
                  blocks=_split_blocks([s for s in rows if s.version == v]))
        out[v] = len(admonitions(ctx))
    return out


#: What the catch-all reads, per direction. An upgrade advisory that quotes the
#: *Downgrading* page — and a rollback advisory that quotes *Supported upgrade
#: paths* — is the panel telling an operator about a move they are not making.
_MARKED_SECTIONS = {
    True: tuple(s for s in UPGRADE_SECTIONS if s != "downgrading"),
    False: ("downgrading", "upgrade_notes"),
}


def _rule_marked_caution(ctx: Ctx) -> list[Finding]:
    """Every block the VENDOR marked Caution / Warning / Important.

    The catch-all, and the reason this module does not have to be complete. The
    rules above encode what we understand; this one carries through what we do
    not — prose Fortinet added after this file was written still reaches the
    operator, with no verdict attached and no pretence of one."""
    out = []
    for word, body in admonitions(ctx, *_MARKED_SECTIONS[ctx.is_upgrade]):
        severity = _MARKS[word.lower().rstrip(":")]
        if severity == "note" and len(body.text) < 60:
            continue          # a one-line aside is not an upgrade decision
        out.append(_finding(
            "vendor-marked", severity, _headline(word, body.text, body.section),
            "Fortinet flagged this themselves. SATOM has no tailored verdict for "
            "it — read the vendor's words and decide.", body))
    return out


#: Sections whose ENTIRE subject is a floor: their prose is about upgrading
#: from below a version, and the tailored rule beside them is the thing that
#: knows whether the move goes near it. If that rule stayed quiet, the
#: catch-all must stay quiet too — an 8.0.6 → 8.0.7 hop warned about
#: repartitioning a pre-5.5 disk, and noise like that is what gets a panel
#: closed before the row that mattered is read.
SECTION_GATED_BY: dict[str, str] = {
    "repartitioning": "repartition",
    "vm_license": "vm-license",
}

#: A floor stated INSIDE a block ("previous to 5.5.4", "earlier than 6.3.0").
#: Compared against the LOWER endpoint of the move, which is the current
#: version on an upgrade and the target on a rollback — so one comparison
#: covers both directions.
_RE_FLOOR = re.compile(
    r"(?:previous to|prior to|earlier than|lower than)\s+(" + _VER + r")", re.I)

#: The same floor written the other way round: "To upgrade from 4.0 MR4, Patch x
#: or earlier, please contact Support". Without this spelling, that Note rode
#: along on every advisory in the corpus as a caveat about a firmware line
#: retired a decade ago — and noise is what gets the row that matters skipped.
_RE_FLOOR_SUFFIX = re.compile(
    r"(" + _VER + r")\b[^.]{0,40}?\bor (?:earlier|lower|below)\b", re.I)


def _floor_excludes(text: str, ctx: Ctx) -> bool:
    """True when the vendor named a floor the move never goes near.

    Compared against the LOWER endpoint of the move — the current version on an
    upgrade, the target on a rollback — so one comparison serves both
    directions. One author for this, shared by the catch-all filter and by the
    destination-scoped rule: a prohibition that carries its own floor
    ("not supported to upgrade to 8.0.5 from versions earlier than 6.3.0") is a
    blocker for an appliance below that floor and a false alarm for every other
    one, and a second copy of this comparison is how those drift apart."""
    lo = min(ctx.cur_t, ctx.tgt_t)
    for rx in (_RE_FLOOR, _RE_FLOOR_SUFFIX):
        m = rx.search(text)
        if m and lo >= version_tuple(m.group(1)):
            return True
    return False

#: The MIRROR of a floor: "Version 7.6.2 introduces an expanded partition size".
#: This one applies when the named version IS crossed, not when the move starts
#: below it — the opposite comparison, so it cannot share the regex above. The
#: block it drops is the one an 8.0.6 → 8.0.7 hop was still being shown, about a
#: partition change two releases behind it.
_RE_INTRODUCED = re.compile(
    r"[Vv]ersion\s+(" + _VER + r")\s+introduce", re.I)


def _drop_inapplicable(found: list[Finding], ctx: Ctx) -> list[Finding]:
    """Filter the CATCH-ALL only. A tailored rule already knows its own
    applicability; this is for the blocks we carry through without a verdict,
    where the only thing we can read is the floor the vendor wrote down."""
    fired = {f.rule for f in found}
    out = []
    for f in found:
        if f.rule != "vendor-marked":
            out.append(f)
            continue
        gate = SECTION_GATED_BY.get(f.section)
        if gate and gate not in fired:
            continue
        if _floor_excludes(f.evidence, ctx):
            continue
        m = _RE_INTRODUCED.search(f.evidence)
        if m and not ctx.crossed(m.group(1)):
            continue
        out.append(f)
    return out


#: The single author of every verdict, in evaluation order.
RULES: tuple = (
    _rule_target_prohibition,
    _rule_mandatory_hop,
    _rule_free_space,
    _rule_repartition,
    _rule_downgrade,
    _rule_backup_not_restorable,
    _rule_vm_license,
    _rule_ha,
    _rule_stated_path,
    _rule_marked_caution,
)


def rules_digest() -> str:
    """A seal over the RULES' own source.

    Stamped onto every report so an archived advisory names the rule set that
    produced it. Hashing the source (not a hand-bumped version string) is the
    point: a threshold edited inside a rule changes this digest in the same
    commit, which a version string would not."""
    h = hashlib.sha256()
    for fn in RULES:
        h.update(fn.__name__.encode())
        h.update(inspect.getsource(fn).encode())
    return h.hexdigest()[:16]


# --------------------------------------------------------------------------- #
#  Orchestration                                                                #
# --------------------------------------------------------------------------- #
def _split_blocks(sections: list[ReleaseSection]) -> list[Block]:
    out: list[Block] = []
    for sec in sections:
        for raw in (sec.content or "").split("\n"):
            t = raw.strip()
            if not t:
                continue
            out.append(Block(version=sec.version, section=sec.section, text=t,
                             source_url=sec.source_url, index=len(out)))
    return out


def span_versions(current: str, target: str, known: list[str]) -> list[str]:
    """Every version the move spans, INCLUSIVE of both endpoints.

    ONE author for this notion on purpose: coverage and rule input must agree by
    construction. Derived from ``known`` PLUS the two endpoints — never from
    ``known`` alone, because a version missing from the corpus is exactly what
    has to surface as a gap, and a span derived only from what we hold would make
    every gap invisible."""
    ct, tt = version_tuple(current), version_tuple(target)
    lo, hi = (ct, tt) if tt > ct else (tt, ct)
    seen = {v for v in known if lo <= version_tuple(v) <= hi}
    seen |= {current, target}
    return sorted(seen, key=version_key)


def analyse(sections: list[ReleaseSection], current: str, target: str, *,
            product: str = "fortiweb") -> Advisory:
    """Findings for moving ``current`` → ``target``, over the harvested prose."""
    rows = [s for s in sections if s.product == product]
    known = sorted({s.version for s in rows}, key=version_key)
    harvested = {s.version for s in rows}
    is_upgrade = version_tuple(target) > version_tuple(current)
    span = span_versions(current, target, known)

    have = {(s.version, s.section) for s in rows}
    read: list[Gap] = []
    gaps: list[Gap] = []
    for v in span:
        for sec in UPGRADE_SECTIONS:
            if (v, sec) in have:
                read.append(Gap(version=v, section=sec, reason=""))
            else:
                gaps.append(Gap(version=v, section=sec,
                                reason=GAP_STALE if v in harvested else GAP_ABSENT))

    ctx = Ctx(current=current, target=target, is_upgrade=is_upgrade,
              blocks=_split_blocks([s for s in rows if s.version in span
                                    and s.section in UPGRADE_SECTIONS]))
    found: list[Finding] = []
    for fn in RULES:
        found.extend(fn(ctx))
    found = _drop_inapplicable(_dedupe(found), ctx)
    found.sort(key=lambda f: (_SEV_RANK.get(f.severity, 9),
                              _RULE_RANK.get(f.rule, len(RULE_ORDER)),
                              version_key(f.version), f.title))

    path = _path_from(found, current, target)
    verdict = _verdict(found, gaps, span)
    return Advisory(current=current, target=target, is_upgrade=is_upgrade,
                    verdict=verdict, findings=found, path=path, gaps=gaps,
                    read=read, rules_digest=rules_digest(),
                    generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))


#: How each rule collapses across the versions crossed. Declared, not inferred,
#: because the two policies answer different questions:
#:
#: ``fact``     — the rule states ONE fact about the move, so the newest version's
#:                phrasing wins and the rest are the same sentence reprinted. A
#:                rule that extracts several DISTINCT facts keeps them apart via
#:                ``Finding.data`` (two different mandatory hops survive; the same
#:                hop repeated across six versions does not).
#: ``evidence`` — the rule carries the vendor's blocks through, so each distinct
#:                block is its own item. Collapsing these would silently drop
#:                warnings.
COLLAPSE: dict[str, str] = {"vendor-marked": "evidence",
                            "target-prohibition": "evidence"}


def _dedupe(found: list[Finding]) -> list[Finding]:
    """Collapse repeats, then let a tailored verdict beat the catch-all.

    Several of these pages are byte-identical across versions (``repartitioning``
    is verbatim from 7.6 to 8.0) and the rest restate the same paragraph, so
    without this the panel prints the same blocker once per version crossed.

    The second pass matters just as much: the catch-all quotes the vendor's
    Caution blocks, and the tailored rules were WRITTEN from those same blocks —
    so the 1.5 GB prerequisite arrived twice, once as a blocker with an
    instruction and once as a caution that says 'decide for yourself'. The
    weaker, redundant copy is the one that goes."""
    best: dict[tuple, Finding] = {}
    for f in found:
        if COLLAPSE.get(f.rule) == "evidence":
            k = (f.rule, f.title, f.evidence)
        else:
            k = (f.rule, f.title, tuple(sorted(f.data.items())))
        cur = best.get(k)
        if cur is None or version_key(f.version) > version_key(cur.version):
            best[k] = f
    kept = list(best.values())
    claimed = {f.evidence for f in kept if f.rule != "vendor-marked"}
    return [f for f in kept if f.rule != "vendor-marked" or f.evidence not in claimed]


def _path_from(found: list[Finding], current: str, target: str) -> list[str]:
    """The hop sequence implied by the mandatory-hop findings.

    Reads ``Finding.data["hop"]`` — the value the rule extracted — and NOT the
    prose of ``detail``. Re-parsing our own sentence would tie the route an
    operator follows to the wording of a caption."""
    hops = sorted({f.data.get("hop") for f in found
                   if f.rule == "mandatory-hop" and f.data.get("hop")},
                  key=version_key)
    return [current, *hops, target] if hops else []


def _verdict(found: list[Finding], gaps: list[Gap], wanted: list[str]) -> str:
    """``unknown`` outranks a clean result, and that is the whole discipline.

    An advisory rendered over prose we never harvested would read exactly like an
    advisory over prose that said nothing — and only one of those is a finding."""
    if not wanted:
        return "unknown"
    if any(f.severity == "blocker" for f in found):
        return "blocker"
    if gaps:
        return "unknown"
    if any(f.severity == "caution" for f in found):
        return "caution"
    return "clear"


__all__ = [
    "SEVERITIES", "Block", "Finding", "Gap", "Advisory", "Ctx",
    "GAP_ABSENT", "GAP_STALE", "span_versions", "RULE_ORDER", "SECTION_GATED_BY",
    "RULES", "rules_digest", "analyse",
    "TARGET_SCOPED", "admonitions", "admonition_coverage",
]
