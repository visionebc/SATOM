"""Guards for the two blind spots that let a *"do not upgrade"* stay invisible.

Every sentence quoted below is VERBATIM from ``docs.fortinet.com`` (FortiWeb
8.0.7 and 7.6.5, harvested 2026-09-14) and is reproduced from the live corpus,
not retyped from the page. That is the whole discipline of this file: the defect
it defends against was a rule written for prose that looked the way I expected,
over a corpus that had quietly stopped looking that way.

What failed, and how silently:

* **The catch-all could only read one renderer.** It fired on a line that IS a
  mark word (``Warning`` alone, then the body) — the markdown docset's shape.
  MadCap glues the mark to the sentence (``Note : This issue has been…``), so
  measured over the live corpus the catch-all found **zero** marked blocks in
  every FortiWeb release from 7.6.5 to 8.0.6 and eighteen in 8.0.7. Eleven
  releases of caveats, carried by nothing, with no test red and no log line.
* **Every rule needed a FLOOR.** They all ask "does the move start low enough
  for this to bite?". *"If you are running FortiWeb in a VM environment and the
  total number of configured server policies exceeds 20, do not upgrade to
  FortiWeb 8.0.7 at this time"* has no floor at all: it is true from 8.0.6 and
  true from 7.2.1 alike. The sentence sat in the corpus, correctly harvested,
  and the advisory answered *caution* for every origin anyone could pick.

So the guards here are of three kinds, and the third is the one that matters
most: a COVERAGE guard that fails when a harvested version yields no readable
admonition at all. The other two prove today's parser reads today's prose; only
that one notices the day Fortinet change renderers again.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.services import release_advisor as ra
from app.services.release_notes import (
    UPGRADE_SECTIONS, ReleaseSection, version_tuple,
)

P = "fortiweb"


def _sec(version, section, *lines):
    return ReleaseSection(
        product=P, version=version, section=section, title=section,
        content="\n".join(lines),
        source_url=f"https://docs.fortinet.com/document/fortiweb/{version}/x")


def _ctx(sections, current, target):
    rows = [s for s in sections if s.section in UPGRADE_SECTIONS]
    return ra.Ctx(current=current, target=target,
                  is_upgrade=version_tuple(target) > version_tuple(current),
                  blocks=ra._split_blocks(rows))


# --- verbatim vendor prose --------------------------------------------------- #
#: The MadCap shape. The mark is INSIDE the sentence, and the space before the
#: colon is Fortinet's, not a typo here — a parser tightened to ``Note:`` alone
#: stops reading this and nothing says so.
MADCAP_NOTE = (
    "Note : This issue has been resolved in versions 7.2.10, 7.4.5, 7.6.1, and "
    "later. If you are upgrading from these versions, the recommended workaround "
    "is unnecessary.")

#: The markdown shape: the mark alone on its line, body in the block after it.
MARKDOWN_MARK = "Caution"
MARKDOWN_BODY = (
    "Version 7.6.2 introduces an expanded partition size. Ensure the log disk "
    "has at least 1.5 GB of free space before upgrading.")

#: The prohibition, with the vendor's own heading above it. Unmarked prose: no
#: Caution, no Warning, nothing for a mark-based catch-all to find.
VM_HEADING = "FortiWeb-VM Upgrade Limitation for FortiWeb 8.0.7"
VM_PROHIBITION = (
    "If you are running FortiWeb in a VM environment and the total number of "
    "configured server policies exceeds 20, do not upgrade to FortiWeb 8.0.7 at "
    "this time. This limitation applies only to FortiWeb-VM deployments. "
    "Hardware appliances are not affected.")

#: A prohibition that carries its OWN floor. Same imperative shape, and a
#: blocker for an appliance below 6.3.0 — a false alarm for every other one.
DOCKER_PROHIBITION = (
    "For FortiWeb-VM on docker platform, it's not supported to upgrade to 8.0.5 "
    "from versions earlier than 6.3.0. You need to install FortiWeb-VM 8.0.5 "
    "instead of upgrading to 8.0.5. For how to install, see FortiWeb-VM on "
    "docker .")

#: A floor written the other way round. Retired firmware, so it applies to
#: nobody this advisory can be asked about.
MR4_NOTE = ("Note: To upgrade from 4.0 MR4, Patch x or earlier, please contact "
            "Fortinet Technical Support.")


def _corpus_807():
    return [
        _sec("8.0.7", "upgrade_notes",
             "Upgrade notes and important information",
             "FortiWeb-VM Specific Notes",
             VM_HEADING,
             VM_PROHIBITION),
        _sec("8.0.7", "upgrading_from",
             "Supported upgrade paths",
             MARKDOWN_MARK,
             MARKDOWN_BODY,
             MR4_NOTE),
    ]


# --------------------------------------------------------------------------- #
#  1. Both renderer shapes are admonitions                                      #
# --------------------------------------------------------------------------- #
def test_madcap_embedded_mark_is_an_admonition():
    """The shape that was invisible for eleven releases."""
    ctx = _ctx([_sec("8.0.7", "upgrade_notes", "Heading", MADCAP_NOTE)],
               "8.0.6", "8.0.7")
    found = ra.admonitions(ctx)
    assert [w for w, _ in found] == ["Note"]
    assert found[0][1].text == MADCAP_NOTE


def test_markdown_pure_mark_is_still_an_admonition():
    ctx = _ctx([_sec("8.0.7", "upgrading_from", MARKDOWN_MARK, MARKDOWN_BODY)],
               "7.6.1", "8.0.7")
    found = ra.admonitions(ctx)
    assert [w for w, _ in found] == ["Caution"]
    # The BODY is the evidence, never the bare word "Caution".
    assert found[0][1].text == MARKDOWN_BODY


def test_embedded_mark_needs_a_body_not_just_the_word():
    """``Note :`` with nothing after it is a stray fragment, not an admonition."""
    ctx = _ctx([_sec("8.0.7", "upgrade_notes", "Heading", "Note : see above.")],
               "8.0.6", "8.0.7")
    assert ra.admonitions(ctx) == []


def test_embedded_evidence_stays_verbatim_and_the_title_does_not_repeat_the_mark():
    """The mark is stripped for the TITLE only.

    Titling from the raw body produced rows literally called "Note: Note :",
    because the first sentence of a MadCap admonition IS the word. The evidence
    is the vendor's words and must keep the mark they wrote."""
    ctx = _ctx([_sec("8.0.7", "upgrade_notes", "Heading", MADCAP_NOTE)],
               "8.0.6", "8.0.7")
    [f] = ra._rule_marked_caution(ctx)
    assert f.evidence == MADCAP_NOTE
    assert "Note :" not in f.title
    assert f.title.startswith("Note: This issue has been resolved")


def test_the_vendors_own_mark_word_survives_into_the_title():
    """``Warning`` is Fortinet's word; ``caution`` is our severity bucket.

    Returning the severity from the detector reprinted a vendor *Warning* as
    "Caution: …" — a classification of ours set in the typography of a
    quotation, in a panel whose whole contract is that the vendor's words are
    the vendor's."""
    ctx = _ctx([_sec("8.0.7", "upgrading_from", "Paths", "Warning", MARKDOWN_BODY)],
               "7.6.1", "8.0.7")
    assert [w for w, _ in ra.admonitions(ctx)] == ["Warning"]
    [f] = ra._rule_marked_caution(ctx)
    assert f.title.startswith("Warning:")
    assert f.severity == "caution"        # bucket unchanged, wording preserved


def test_catch_all_reads_only_what_admonitions_returns():
    """One author for "what the vendor marked".

    Behavioural, not textual: the catch-all is driven through a sabotaged
    :func:`admonitions`. A second, private copy of the detection inside the rule
    would keep emitting and this guard would catch it — which is the point, since
    a guard that measures readability through a DIFFERENT reader can stay green
    over a catch-all that has gone blind."""
    ctx = _ctx(_corpus_807(), "7.6.1", "8.0.7")
    assert ra._rule_marked_caution(ctx), "fixture must produce findings at all"
    real = ra.admonitions
    try:
        ra.admonitions = lambda *a, **k: []
        assert ra._rule_marked_caution(ctx) == []
    finally:
        ra.admonitions = real


# --------------------------------------------------------------------------- #
#  2. The destination-scoped class                                              #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("current", ["8.0.6", "8.0.5", "7.6.10", "7.6.5", "7.2.1"])
def test_prohibition_fires_from_every_origin(current):
    """No floor means no origin escapes it. THE regression this class exists for.

    Before the rule, this sentence reached the operator for exactly zero of
    these origins, because every rule in the module compared against a floor and
    this one has none."""
    adv = ra.analyse(_corpus_807(), current, "8.0.7")
    hits = [f for f in adv.findings if f.rule == "target-prohibition"]
    assert len(hits) == 1
    assert hits[0].severity == "blocker"
    assert adv.verdict == "blocker"


def test_prohibition_evidence_is_the_vendor_sentence_verbatim():
    adv = ra.analyse(_corpus_807(), "8.0.6", "8.0.7")
    [f] = [x for x in adv.findings if x.rule == "target-prohibition"]
    assert f.evidence == VM_PROHIBITION
    assert f.data["scope"] == "target"
    assert f.data["named"] == "8.0.7"


def test_prohibition_title_carries_the_vendor_heading():
    """The condition is named where it is read, not buried in the body.

    An unconditional-looking blocker on a conditional limitation is the failure
    mode that gets a panel distrusted; the vendor already wrote the condition as
    a heading, so it is quoted rather than paraphrased."""
    adv = ra.analyse(_corpus_807(), "8.0.6", "8.0.7")
    [f] = [x for x in adv.findings if x.rule == "target-prohibition"]
    assert VM_HEADING in f.title
    assert f.data["condition"] == VM_HEADING


def test_prohibition_ignores_a_version_the_move_only_steps_over():
    """A prohibition binds the version being INSTALLED.

    Gating on "is it inside the span" made 7.2.1 -> 8.0.7 emit a blocker about a
    release that route never lands on. A blocker that does not apply is how the
    row that does apply stops being read."""
    secs = _corpus_807() + [
        _sec("8.0.7", "upgrade_notes",
             "Compatibility Issue with FortiWeb 100D and 7.6.0",
             "For FortiWeb 100D, do not upgrade to 7.6.0.")]
    adv = ra.analyse(secs, "7.2.1", "8.0.7")
    named = {f.data.get("named") for f in adv.findings
             if f.rule == "target-prohibition"}
    assert named == {"8.0.7"}


def test_prohibition_respects_a_floor_the_vendor_stated_in_the_block():
    """Same imperative, but the vendor scoped it. Above the floor it is noise."""
    secs = [_sec("8.0.5", "upgrading_from", "Supported upgrade paths",
                 DOCKER_PROHIBITION)]
    assert not [f for f in ra.analyse(secs, "7.6.5", "8.0.5").findings
                if f.rule == "target-prohibition"]
    below = [f for f in ra.analyse(secs, "6.2.0", "8.0.5").findings
             if f.rule == "target-prohibition"]
    assert [f.severity for f in below] == ["blocker"]


def test_prohibition_is_silent_on_a_rollback():
    """A rollback advisory quoting an upgrade prohibition describes a move the
    operator is not making.

    The fixture names the ROLLBACK TARGET in the prohibition on purpose. An
    earlier version of this guard reused the 8.0.7 corpus, where the prohibition
    names 8.0.7 — the version being left, not the one being installed — so the
    destination check alone already dropped it and the guard passed without the
    direction check running at all. A mutation that deleted that check survived
    against a fixture that could not exercise it."""
    secs = [
        _sec("7.6.5", "upgrade_notes",
             "Upgrade notes and important information",
             "FortiWeb-VM Upgrade Limitation for FortiWeb 7.6.5",
             "If you are running FortiWeb in a VM environment and the total "
             "number of configured server policies exceeds 20, do not upgrade "
             "to FortiWeb 7.6.5 at this time."),
    ]
    # Upgrading INTO it: the rule is the whole reason this module exists.
    up = ra.analyse(secs, "7.6.1", "7.6.5")
    assert [f.rule for f in up.findings if f.rule == "target-prohibition"] == \
        ["target-prohibition"]
    # Rolling BACK into it: same sentence, same destination, and it is prose
    # about upgrading — the rollback is not the move it describes.
    down = ra.analyse(secs, "8.0.7", "7.6.5")
    assert not [f for f in down.findings if f.rule == "target-prohibition"]


def test_prohibition_outranks_the_hop_it_would_otherwise_sit_under():
    """"There is no window" is read before "the window needs two halves".

    Without a declared rank the fallback is the rule id's spelling, and
    "mandatory-hop" sorts above "target-prohibition"."""
    secs = _corpus_807() + [
        _sec("8.0.7", "upgrading_from", "Supported upgrade paths",
             "If you are upgrading from a version that is 7.6.1 or lower, then "
             "you will need to upgrade to version 7.6.2 before proceeding.")]
    adv = ra.analyse(secs, "7.6.1", "8.0.7")
    order = [f.rule for f in adv.findings if f.severity == "blocker"]
    assert order[0] == "target-prohibition"
    assert "mandatory-hop" in order


def test_every_rule_id_has_a_declared_rank_and_scope():
    """A rule missing from RULE_ORDER sorts by nothing and moves silently."""
    secs = _corpus_807() + [
        _sec("8.0.7", "ha_upgrade", "Upgrading an HA cluster",
             "You only need to upgrade the active appliance: it automatically "
             "upgrades the standby.")]
    emitted = set()
    for cur, tgt in (("7.2.1", "8.0.7"), ("8.0.7", "7.6.5")):
        emitted |= {f.rule for f in ra.analyse(secs, cur, tgt).findings}
    assert emitted, "fixture must emit something"
    assert emitted <= set(ra.RULE_ORDER)
    assert ra.TARGET_SCOPED <= set(ra.RULE_ORDER)


# --------------------------------------------------------------------------- #
#  3. The floor spelt the other way round                                       #
# --------------------------------------------------------------------------- #
def test_or_earlier_is_read_as_a_floor():
    """"4.0 MR4, Patch x or earlier" is a floor, and it applies to nobody here.

    Only ``previous to`` / ``earlier than`` were understood, so this Note rode
    along on every advisory in the corpus as a caveat about firmware retired a
    decade ago."""
    secs = [_sec("8.0.7", "upgrading_from", "Supported upgrade paths",
                 "Note", MR4_NOTE)]
    kept = [f for f in ra.analyse(secs, "7.6.5", "8.0.7").findings
            if MR4_NOTE in f.evidence]
    assert kept == []


def test_a_floor_below_the_move_still_lets_the_block_through():
    """The filter drops what does not apply — not everything with a number in it."""
    secs = [_sec("8.0.7", "upgrading_from", "Supported upgrade paths",
                 "Note", MR4_NOTE)]
    kept = [f for f in ra.analyse(secs, "3.5.0", "8.0.7").findings
            if MR4_NOTE in f.evidence]
    assert len(kept) == 1


# --------------------------------------------------------------------------- #
#  4. COVERAGE — the guard that notices the NEXT renderer change                #
# --------------------------------------------------------------------------- #
def test_coverage_counts_both_shapes():
    secs = [_sec("7.6.5", "upgrade_notes", "Heading", MADCAP_NOTE),
            _sec("8.0.7", "upgrading_from", "Paths", MARKDOWN_MARK, MARKDOWN_BODY)]
    assert ra.admonition_coverage(secs) == {"7.6.5": 1, "8.0.7": 1}


def test_coverage_reports_zero_for_a_version_the_parser_cannot_read():
    """A zero is the finding. Fortinet mark the upgrade pages of every release,
    so "no marked blocks" never means "nothing to warn about" — it means the
    parser and the renderer have parted company."""
    secs = [_sec("9.9.9", "upgrade_notes", "Heading",
                 "[!NOTE] a shape nobody has written a reader for yet")]
    assert ra.admonition_coverage(secs) == {"9.9.9": 0}


def _live_corpus():
    for p in (Path("/opt/satom/data/reports/_release_notes.json"),
              Path(__file__).resolve().parents[1] / "data/reports/_release_notes.json"):
        if p.is_file():
            return json.loads(p.read_text(encoding="utf-8"))
    return None


def test_live_corpus_has_no_blind_version():
    """THE guard. Every harvested version must yield at least one admonition.

    This is the only assertion in the file that could have caught the original
    defect, because it is the only one that does not already know what the prose
    looks like. It reads whatever is on disk and fails on silence.

    Skipped where no corpus exists (a fresh install, CI): a version that was
    never harvested is a different problem, and failing on it here would train
    the team to ignore this test."""
    db = _live_corpus()
    if not db:
        pytest.skip("no harvested corpus on this node")
    secs = [ReleaseSection(**s) for s in db.get("sections", [])]
    cov = ra.admonition_coverage(secs)
    if not cov:
        pytest.skip("corpus holds no fortiweb upgrade sections")
    blind = sorted(v for v, n in cov.items() if n == 0)
    assert not blind, (
        f"{len(blind)} harvested version(s) yield ZERO readable admonitions: "
        f"{blind}. Fortinet mark the upgrade pages of every release, so this is "
        f"a parser that no longer matches the renderer — not a quiet release. "
        f"Coverage: {cov}")


# --------------------------------------------------------------------------- #
#  5. The panel and the rule must agree on what "destination-scoped" is called  #
# --------------------------------------------------------------------------- #
def _js_without_comments(text: str) -> str:
    """Strip ``//`` and ``/* */`` so a guard cannot match its own explanation.

    Seventh time this trap has been paid for in this repo: the comment that
    explains why a branch exists has to name the thing the branch tests, so an
    assertion over raw source is satisfied by prose. What is being defended is
    CODE."""
    out = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", out)


def test_the_panel_reads_the_scope_value_the_rule_actually_emits():
    """One author for the string ``"target"``.

    The expected value is taken from a REAL finding, not typed here: a rename in
    the Python rule with the JS left behind would otherwise pass, and the panel
    would silently stop printing "this holds no matter which version you upgrade
    from" — the one line that stops an operator trying to hop around a
    prohibition no hop can clear."""
    adv = ra.analyse(_corpus_807(), "8.0.6", "8.0.7")
    [f] = [x for x in adv.findings if x.rule == "target-prohibition"]
    scope = f.data["scope"]
    js = _js_without_comments(
        (Path(ra.__file__).resolve().parents[1]
         / "static/js/release_notes.js").read_text(encoding="utf-8"))
    assert f"f.data.scope === '{scope}'" in js, (
        f"the advisory panel does not branch on scope {scope!r}")
    assert "f.data.named" in js and "f.data.condition" in js
