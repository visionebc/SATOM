"""Guards for Scout's upgrade advisory.

The prose below is VERBATIM from docs.fortinet.com (FortiWeb 8.0.7, fetched
2026-09-13), trimmed but not reworded. That matters more here than anywhere else
in the suite: a rule written against a sentence I paraphrased would pass this
file and miss the live page, which is precisely the failure it is meant to
prevent. If Fortinet rewrite these sentences these tests keep passing and the
live advisory goes quiet — so the catch-all rule (``vendor-marked``) exists to
carry through what no tailored rule recognises, and it is guarded too.

What is being defended, in order of how badly it fails:

* a BLOCKER that does not fire — the operator books one window for a two-window
  job and finds out at 02:00;
* a blocker that fires when it should not — the panel gets ignored, and then the
  first failure applies again;
* a CLEAN verdict over prose nobody harvested — the worst of the three, because
  it is indistinguishable from a real all-clear.
"""
from __future__ import annotations

from app.services import release_advisor as ra
from app.services.release_notes import ReleaseSection

P = "fortiweb"


def _sec(version, section, content):
    return ReleaseSection(
        product=P, version=version, section=section, title=section,
        content=content,
        source_url=f"https://docs.fortinet.com/document/fortiweb/{version}/x")


# --- verbatim vendor prose --------------------------------------------------- #
UPGRADING_FROM = "\n".join([
    "Supported upgrade paths",
    "This section discusses the general paths to upgrade FortiWeb from previous releases.",
    "If you are upgrading from a version that is 7.6.1 or lower, then you will need to "
    "upgrade to version 7.6.2 before proceeding with subsequent updates.",
    "For example, to upgrade from 7.2.1 to 8.0.7, you will follow the upgrade path below:",
    "7.2.1 → 7.6.2 → 8.0.7",
    "Caution",
    "Version 7.6.2 introduces an expanded partition size. Ensure the log disk has at "
    "least 1.5 GB of free space before upgrading.",
    "To upgrade from FortiWeb 7.4.x to 7.6.2",
    "Upgrade directly.",
    # A marked block with NO version the filters can read — "since 6.3.3" is
    # neither a floor ("previous to") nor an introduction ("Version X
    # introduces"). Without it, every marked block on this page was already
    # dropped by the floor filter, and the direction-scope guard below passed
    # for the wrong reason: a mutation that let a rollback quote this page
    # survived the final run.
    "Warning",
    "The \"Bad Robot\" and \"SQL Injection (Syntax Based Detection)\" signatures had "
    "been integrated into WAF modules \"Bot Mitigation > Known Bots\" and \"SQL/XSS "
    "Syntax Based Detection\" since 6.3.3.",
])

UPGRADE_NOTES = "\n".join([
    "Upgrade notes and important information",
    "Backup Restoration Issue After Enabling Private Encryption Key",
    "When private-encryption-key is enabled with the following commands in versions "
    "prior to 7.6.3, backup files may no longer be restorable after the upgrade. To "
    "avoid this issue, please ensure you create a new backup after upgrading to "
    "version 7.6.3.",
])

HA_UPGRADE = "\n".join([
    "Upgrading an HA cluster",
    "If the HA cluster is running FortiWeb 4.0 MR4 or later, the HA cluster upgrade is "
    "streamlined. When you upgrade the active appliance, it automatically upgrades any "
    "standby appliance(s), too; no manual intervention is required to upgrade the other "
    "appliance(s).",
])

DOWNGRADING = "\n".join([
    "Downgrading to a previous release",
    "Note",
    "We don't recommend performing a downgrade because unexpected results may occur. "
    "If you insist on a downgrade, please first contact FortiWeb Technical Support team.",
    "ML based modules data loss",
    "The machine learning data will be lost if you downgrade to versions lower than "
    "6.2.0. It cannot be recovered because the database architecture is changed since "
    "6.2.0.",
    "Admin user password hash change",
    "The admin user password hash is changed from sha1 to sha256 since 7.2.0. If you "
    "downgrade to 7.0.x and 7.1.x, you may need to convert password hash otherwise the "
    "admin users can't log in with their credentials.",
])

REPARTITIONING = "\n".join([
    "Repartitioning the hard disk",
    "To upgrade from a version of FortiWeb previous to 5.5, you must first resize your "
    "FortiWeb operating system's disk.",
    # The real page carries a Warning block, and it MUST be here: without it the
    # catch-all produces nothing from this section, and the section-gate guard
    # below passes for the wrong reason. It did — a mutation that emptied
    # SECTION_GATED_BY survived the first run against this fixture.
    "Warning",
    "Repartitioning affects the operating system's disk (USB/flash disk), not the hard "
    "disk. Existing data such as reports and event, traffic, and attack logs, which are "
    "on the hard disk, are not affected.",
])

VM_LICENSE = "\n".join([
    "FortiWeb-VM license validation after upgrade from pre-5.4 version",
    "On some virtual machine deployments, upgrading FortiWeb-VM from a version previous "
    "to 5.4 changes the virtual machine's universal unique identifier (UUID). Because of "
    "this change, the first time you upload your existing FortiWeb-VM license, the "
    "FortiGuard Distribution Network (FDN) server reports that it is invalid.",
])


def corpus(*versions):
    """The full upgrade branch, for each named version."""
    out = []
    for v in versions:
        out += [
            _sec(v, "upgrading_from", UPGRADING_FROM),
            _sec(v, "upgrade_notes", UPGRADE_NOTES),
            _sec(v, "ha_upgrade", HA_UPGRADE),
            _sec(v, "downgrading", DOWNGRADING),
            _sec(v, "repartitioning", REPARTITIONING),
            _sec(v, "vm_license", VM_LICENSE),
        ]
    return out


FULL = corpus("7.6.9", "7.6.10", "8.0.5", "8.0.6", "8.0.7")


def rules(adv):
    return [f.rule for f in adv.findings]


def by_rule(adv, rule):
    return [f for f in adv.findings if f.rule == rule]


# --------------------------------------------------------------------------- #
#  The blocker that started this                                                #
# --------------------------------------------------------------------------- #
def test_a_mandatory_intermediate_hop_is_a_blocker():
    """A MINOR release announcing a two-step upgrade.

    Nothing about 8.0.7's version number says 'you cannot get here from 7.6.1',
    which is exactly why a human skims past it."""
    a = ra.analyse(corpus("7.6.1", "8.0.7"), "7.6.1", "8.0.7")
    hop = by_rule(a, "mandatory-hop")
    assert hop, rules(a)
    assert hop[0].severity == "blocker"
    assert hop[0].data == {"floor": "7.6.1", "hop": "7.6.2"}
    assert a.verdict == "blocker"


def test_the_required_route_is_drawn_from_the_rule_not_from_our_prose():
    a = ra.analyse(corpus("7.6.1", "8.0.7"), "7.6.1", "8.0.7")
    assert a.path == ["7.6.1", "7.6.2", "8.0.7"]


def test_an_operator_above_the_floor_is_not_sent_on_a_detour():
    """A blocker that fires when it should not is how a panel gets ignored."""
    a = ra.analyse(FULL, "7.6.9", "8.0.7")
    assert not by_rule(a, "mandatory-hop"), rules(a)
    assert a.path == []


def test_the_evidence_is_the_vendors_words_verbatim():
    """We paraphrase in ``detail`` and never in ``evidence``. A rule that quietly
    rewords a vendor prerequisite is worse than no rule: it is believed."""
    a = ra.analyse(corpus("7.6.1", "8.0.7"), "7.6.1", "8.0.7")
    ev = by_rule(a, "mandatory-hop")[0].evidence
    assert ev in UPGRADING_FROM
    assert "7.6.1 or lower" in ev


# --------------------------------------------------------------------------- #
#  Prerequisites, gated on what the move actually crosses                       #
# --------------------------------------------------------------------------- #
def test_the_free_space_prerequisite_fires_when_its_version_is_crossed():
    a = ra.analyse(corpus("7.6.1", "8.0.7"), "7.6.1", "8.0.7")
    f = by_rule(a, "free-space")
    assert f and f[0].severity == "blocker"
    assert "1.5 GB" in f[0].title


def test_the_free_space_prerequisite_is_silent_when_its_version_is_not_crossed():
    """7.6.9 is already past 7.6.2. Repeating a prerequisite that belongs to a hop
    you are not making is noise, and noise is what gets the panel ignored."""
    a = ra.analyse(FULL, "7.6.9", "8.0.7")
    assert not by_rule(a, "free-space"), rules(a)


def test_the_pre_5_5_repartition_rule_never_fires_on_a_modern_version():
    a = ra.analyse(FULL, "7.6.9", "8.0.7")
    assert not by_rule(a, "repartition")


def test_the_repartition_rule_does_fire_below_its_floor():
    """The floor is read from the prose, not hard-coded — so this proves the rule
    is gated rather than dead."""
    a = ra.analyse(corpus("5.4.0", "8.0.7"), "5.4.0", "8.0.7")
    f = by_rule(a, "repartition")
    assert f and f[0].severity == "blocker"


def test_the_vm_licence_trap_is_gated_on_its_own_floor():
    assert not by_rule(ra.analyse(FULL, "7.6.9", "8.0.7"), "vm-license")
    assert by_rule(ra.analyse(corpus("5.2.0", "8.0.7"), "5.2.0", "8.0.7"), "vm-license")


def test_a_backup_that_will_not_restore_is_raised_before_the_window():
    """Inverts the reflex: 'take a backup first' is the habit, and here the
    backup is the thing that stops being useful."""
    a = ra.analyse(corpus("7.6.1", "8.0.7"), "7.6.1", "8.0.7")
    f = by_rule(a, "backup-not-restorable")
    assert f and f[0].severity == "caution"


def test_that_backup_trap_is_silent_above_its_floor():
    a = ra.analyse(FULL, "7.6.9", "8.0.7")
    assert not by_rule(a, "backup-not-restorable")


# --------------------------------------------------------------------------- #
#  HA — good news is still news                                                 #
# --------------------------------------------------------------------------- #
def test_the_cluster_behaviour_is_stated():
    """An operator who does not know the active member drags the standby with it
    books a second window and a second outage for nothing."""
    a = ra.analyse(FULL, "7.6.9", "8.0.7")
    f = by_rule(a, "ha-automatic")
    assert f and f[0].severity == "note"


# --------------------------------------------------------------------------- #
#  A rollback is a different question                                           #
# --------------------------------------------------------------------------- #
def test_a_rollback_is_flagged_as_not_routine():
    a = ra.analyse(FULL, "8.0.7", "7.6.9")
    assert a.is_upgrade is False
    assert by_rule(a, "downgrade-discouraged")
    assert a.verdict == "blocker"


def test_destroyed_data_is_a_blocker_only_when_the_floor_is_crossed():
    below = ra.analyse(corpus("6.1.0", "8.0.7"), "8.0.7", "6.1.0")
    assert by_rule(below, "downgrade-data-loss")
    above = ra.analyse(FULL, "8.0.7", "7.6.9")
    assert not by_rule(above, "downgrade-data-loss")


def test_the_admin_lockout_trap_is_raised_once():
    a = ra.analyse(FULL, "8.0.7", "7.6.9")
    assert len(by_rule(a, "downgrade-admin-hash")) == 1


def test_upgrade_rules_stay_quiet_on_a_rollback_and_the_reverse():
    down = ra.analyse(FULL, "8.0.7", "7.6.9")
    assert not [f for f in down.findings
                if f.rule in ("mandatory-hop", "free-space", "repartition")]
    up = ra.analyse(corpus("7.6.1", "8.0.7"), "7.6.1", "8.0.7")
    assert not [f for f in up.findings if f.rule.startswith("downgrade-")]


def test_a_rollback_advisory_never_quotes_the_upgrade_path_page():
    """Scope, not severity. An advisory for a move you are not making is a panel
    asking to be closed.

    Both halves, because only the pair proves the SCOPE is doing the work: the
    signatures Warning carries no version any filter can read, so it survives on
    an upgrade and can only be removed from a rollback by the direction rule."""
    up = ra.analyse(FULL, "7.6.9", "8.0.7")
    assert [f for f in up.findings if "Bad Robot" in f.evidence], \
        "the block must be carried through on an UPGRADE"
    down = ra.analyse(FULL, "8.0.7", "7.6.9")
    assert not [f for f in down.findings if f.section == "upgrading_from"], \
        [(f.rule, f.section) for f in down.findings]


# --------------------------------------------------------------------------- #
#  The catch-all                                                                #
# --------------------------------------------------------------------------- #
def test_prose_no_tailored_rule_understands_still_reaches_the_operator():
    """The reason this module does not have to be complete."""
    novel = _sec("8.0.8", "upgrade_notes",
                 "Upgrade notes\nWarning\nThe frobnicator index is rebuilt during "
                 "the upgrade and traffic is not inspected for up to four minutes, "
                 "which is a thing this module has never heard of.")
    a = ra.analyse(FULL + [novel], "8.0.7", "8.0.8")
    marked = by_rule(a, "vendor-marked")
    assert any("frobnicator" in f.evidence for f in marked), rules(a)
    assert all(f.severity == "caution" for f in marked
               if "frobnicator" in f.evidence)


def test_the_catch_all_does_not_shadow_a_tailored_verdict():
    """The 1.5 GB block is BOTH a vendor Caution and the source of the free-space
    blocker. Printed twice, the weaker copy — 'decide for yourself' — sits under
    an instruction that already told the operator what to do."""
    a = ra.analyse(corpus("7.6.1", "8.0.7"), "7.6.1", "8.0.7")
    cited = [f.evidence for f in a.findings if "1.5 GB" in f.evidence]
    assert len(cited) == 1, [f.rule for f in a.findings if "1.5 GB" in f.evidence]
    assert by_rule(a, "free-space")


def test_a_marked_block_never_picks_up_another_rows_paragraph():
    """Block positions used to be counted per SECTION, so two rows for the same
    (version, section) gave every block a duplicate index and the lookup crossed
    between them. A Caution quoting somebody else's sentence is the worst failure
    available to a rule whose whole contract is that the evidence is verbatim."""
    a = _sec("8.0.9", "upgrade_notes", "Upgrade notes\nWarning\nAAA " + "a" * 70)
    b = _sec("8.0.9", "upgrade_notes", "Upgrade notes\nWarning\nBBB " + "b" * 70)
    adv = ra.analyse(FULL + [a, b], "8.0.7", "8.0.9")
    ev = [f.evidence for f in by_rule(adv, "vendor-marked") if f.version == "8.0.9"]
    assert len(ev) == 2, ev
    assert any(e.startswith("AAA") for e in ev), ev
    assert any(e.startswith("BBB") for e in ev), ev
    assert all(e.startswith(("AAA", "BBB")) for e in ev), ev


def test_a_marked_block_with_nothing_after_it_is_not_a_finding():
    dangling = _sec("8.0.8", "upgrade_notes", "Upgrade notes\nWarning")
    a = ra.analyse(FULL + [dangling], "8.0.7", "8.0.8")
    assert not [f for f in a.findings if f.version == "8.0.8"]


# --------------------------------------------------------------------------- #
#  Collapsing across versions                                                   #
# --------------------------------------------------------------------------- #
def test_the_same_sentence_repeated_across_versions_is_stated_once():
    """These pages are byte-identical across a whole line. Without collapsing,
    every blocker is printed once per version crossed."""
    a = ra.analyse(FULL, "7.6.9", "8.0.7")
    for rule in set(rules(a)):
        if rule == "vendor-marked":
            continue
        assert len(by_rule(a, rule)) == 1, (rule, len(by_rule(a, rule)))


def test_the_newest_versions_wording_is_the_one_shown():
    a = ra.analyse(FULL, "7.6.9", "8.0.7")
    for f in a.findings:
        assert f.version == "8.0.7" or f.rule == "vendor-marked", (f.rule, f.version)


def test_two_distinct_vendor_warnings_both_survive():
    """Collapsing the catch-all by rule would silently drop warnings. The two
    policies are declared in ``COLLAPSE`` for exactly this reason."""
    two = _sec("8.0.8", "upgrade_notes",
               "Upgrade notes\nWarning\n" + "A" * 80 + "\nWarning\n" + "B" * 80)
    a = ra.analyse(FULL + [two], "8.0.7", "8.0.8")
    ev = {f.evidence for f in by_rule(a, "vendor-marked") if f.version == "8.0.8"}
    assert len(ev) == 2, ev


def test_two_different_hops_would_both_survive():
    """``fact`` collapsing keys on the extracted data, not on the rule, so a page
    that states two different floors does not lose one of them."""
    other = _sec("8.0.8", "upgrading_from",
                 "Supported upgrade paths\nIf you are upgrading from a version "
                 "that is 6.4.0 or lower, then you will need to upgrade to "
                 "version 7.0.0 before proceeding.")
    a = ra.analyse(corpus("6.3.0", "8.0.7") + [other], "6.3.0", "8.0.8")
    hops = {f.data.get("hop") for f in by_rule(a, "mandatory-hop")}
    assert hops == {"7.6.2", "7.0.0"}, hops


# --------------------------------------------------------------------------- #
#  Reading order, naming, and prose the move cannot reach                       #
#                                                                               #
#  Every guard below exists because the RENDER showed the defect and the suite   #
#  did not: each one was a correct payload, rendered correctly.                  #
# --------------------------------------------------------------------------- #
def test_the_blocker_that_says_you_cannot_get_there_leads():
    """Ordering within a severity was the rule id's spelling.

    "free-space" sorts above "mandatory-hop", so the panel opened with a disk
    prerequisite and the verdict that says the upgrade is not a supported path at
    all sat underneath it."""
    a = ra.analyse(corpus("7.6.1", "8.0.7"), "7.6.1", "8.0.7")
    blockers = [f.rule for f in a.findings if f.severity == "blocker"]
    assert blockers[0] == "mandatory-hop", blockers


def test_every_rule_has_a_declared_place_in_the_reading_order():
    """A rule missing from RULE_ORDER sorts last in silence — which is how a new
    blocker ends up below a note nobody scrolls to."""
    emitted = set()
    for cur, tgt in (("7.6.1", "8.0.7"), ("5.2.0", "8.0.7"), ("8.0.7", "6.1.0")):
        emitted |= {f.rule for f in ra.analyse(corpus(cur, tgt), cur, tgt).findings}
    assert emitted <= set(ra.RULE_ORDER), emitted - set(ra.RULE_ORDER)


def test_carried_through_blocks_are_not_all_called_the_same_thing():
    """Five rows titled "Note in Upgrading from previous releases", stacked, each
    with the same sentence of ours beneath. A list where every row has the same
    name is a list nobody reads — and the row that mattered was in it."""
    a = ra.analyse(FULL, "7.6.9", "8.0.7")
    marked = by_rule(a, "vendor-marked")
    titles = [f.title for f in marked]
    assert len(set(titles)) == len(titles), titles


def test_a_carried_through_title_comes_from_the_block_itself():
    novel = _sec("8.0.8", "upgrade_notes",
                 "Upgrade notes\nWarning\nThe frobnicator index is rebuilt during the "
                 "upgrade. Traffic is not inspected for up to four minutes.")
    a = ra.analyse(FULL + [novel], "8.0.7", "8.0.8")
    f = [x for x in by_rule(a, "vendor-marked") if "frobnicator" in x.evidence]
    assert f and "frobnicator" in f[0].title.lower(), [x.title for x in f]
    assert f[0].title.startswith("Warning:"), f[0].title


def test_prose_about_a_floor_the_move_never_reaches_is_dropped():
    """An 8.0.6 → 8.0.7 hop warned about a pre-5.5.4 upgrade side effect. The
    vendor wrote the floor down; we can read it."""
    old = _sec("8.0.7", "upgrade_notes",
               "Upgrade notes\nNote\nIf you upgrade from a version of FortiWeb "
               "previous to 5.5.4, the upgrade process deletes any HTTP content "
               "routing policies that match X509 certificate content.")
    a = ra.analyse(FULL + [old], "8.0.6", "8.0.7")
    assert not [f for f in a.findings if "5.5.4" in f.evidence],         [f.title for f in a.findings if "5.5.4" in f.evidence]


def test_a_change_INTRODUCED_by_a_version_the_move_does_not_cross_is_dropped():
    """The mirror of a floor, and the opposite comparison.

    "Version 7.6.2 introduces an expanded partition size" was still shown on an
    8.0.6 → 8.0.7 hop — two releases past it — because the tailored rule had
    correctly stayed quiet and the catch-all carried the same block through
    anyway."""
    a = ra.analyse(FULL, "8.0.6", "8.0.7")
    assert not [f for f in a.findings if "expanded partition" in f.evidence], \
        [f.title for f in a.findings if "expanded partition" in f.evidence]


def test_that_same_change_SURVIVES_when_the_move_DOES_cross_it():
    """And the counterweight: crossing 7.6.2 must still raise it — as the
    tailored blocker, which is the one with an instruction attached."""
    a = ra.analyse(corpus("7.6.1", "8.0.7"), "7.6.1", "8.0.7")
    cited = [f for f in a.findings if "expanded partition" in f.evidence]
    assert len(cited) == 1, [f.rule for f in cited]
    assert cited[0].rule == "free-space", cited[0].rule


def test_the_same_prose_SURVIVES_when_the_move_does_cross_that_floor():
    """The counterweight. A filter that only ever removes is indistinguishable
    from a rule that never fires."""
    old = _sec("8.0.7", "upgrade_notes",
               "Upgrade notes\nNote\nIf you upgrade from a version of FortiWeb "
               "previous to 5.5.4, the upgrade process deletes any HTTP content "
               "routing policies that match X509 certificate content.")
    a = ra.analyse(corpus("5.4.0", "8.0.7") + [old], "5.4.0", "8.0.7")
    assert [f for f in a.findings if "5.5.4" in f.evidence]


def test_a_section_that_is_entirely_about_a_floor_stays_quiet_with_its_rule():
    """`repartitioning` is about upgrading from below 5.5 and nothing else. Its
    tailored rule knows whether the move goes near that; the catch-all does not,
    so it follows the rule rather than shouting over it.

    The section's Warning block carries NO version of its own — "Repartitioning
    affects the operating system's disk" is true of any era — so the floor
    filter cannot touch it. The section gate is the only thing that can, which
    is what makes this a guard rather than a coincidence: a mutation that
    emptied SECTION_GATED_BY survived the first run, because the fixture had no
    Warning block for the catch-all to find.
    """
    modern = ra.analyse(FULL, "7.6.9", "8.0.7")
    offenders = [f.title for f in modern.findings if f.section == "repartitioning"]
    assert not offenders, offenders


def test_the_gated_section_DOES_speak_when_its_rule_fires():
    """The counterweight, and the half that was missing.

    A gate that only ever suppresses is indistinguishable from a section nobody
    reads — and the block being suppressed here is a real Warning."""
    ancient = ra.analyse(corpus("5.4.0", "8.0.7"), "5.4.0", "8.0.7")
    assert by_rule(ancient, "repartition"), "the tailored rule must fire here"
    carried = [f for f in ancient.findings
               if f.section == "repartitioning" and f.rule == "vendor-marked"]
    assert carried, [(f.rule, f.section) for f in ancient.findings]
    assert "operating system's disk" in carried[0].evidence


def test_the_gate_applies_to_the_catch_all_and_never_to_a_verdict():
    """A tailored rule already knows its own applicability. Filtering those too
    would let this cleanup silence a blocker."""
    a = ra.analyse(corpus("7.6.1", "8.0.7"), "7.6.1", "8.0.7")
    assert by_rule(a, "mandatory-hop")
    assert by_rule(a, "free-space")


# --------------------------------------------------------------------------- #
#  Absence is not innocence                                                     #
# --------------------------------------------------------------------------- #
def test_an_empty_corpus_is_unknown_and_never_clear():
    a = ra.analyse([], "7.6.9", "8.0.7")
    assert a.verdict == "unknown"
    assert not a.findings
    assert a.gaps


def test_a_partially_harvested_corpus_cannot_produce_a_clean_verdict():
    thin = [s for s in FULL if s.section == "upgrading_from"]
    a = ra.analyse(thin, "7.6.9", "8.0.7")
    assert a.verdict == "unknown", a.verdict
    assert a.gaps


def test_a_gap_says_WHICH_kind_of_gap_it_is():
    """Two different problems, and only one is fixed by pressing Scan again."""
    thin = [s for s in FULL if s.section == "upgrading_from"]
    a = ra.analyse(thin, "7.6.9", "8.0.7")
    assert any(g.reason == ra.GAP_STALE for g in a.gaps)
    b = ra.analyse(FULL, "7.6.8", "8.0.7")      # 7.6.8 was never harvested
    assert any(g.version == "7.6.8" and g.reason == ra.GAP_ABSENT for g in b.gaps)


def test_a_blocker_outranks_a_coverage_gap():
    """An incomplete corpus does not get to soften a blocker that WAS found."""
    thin = [s for s in corpus("7.6.1", "8.0.7") if s.section == "upgrading_from"]
    a = ra.analyse(thin, "7.6.1", "8.0.7")
    assert a.gaps
    assert a.verdict == "blocker"


def test_a_fully_harvested_quiet_range_is_allowed_to_be_clear():
    """The counterweight: if UNKNOWN were the only non-blocker outcome, the
    verdict would carry no information at all."""
    quiet = [_sec(v, sec, sec.replace("_", " ").title() + "\nNothing to report here.")
             for v in ("8.0.6", "8.0.7")
             for sec in ("upgrade_notes", "upgrading_from", "repartitioning",
                         "ha_upgrade", "downgrading", "vm_license")]
    a = ra.analyse(quiet, "8.0.6", "8.0.7")
    assert a.gaps == []
    assert a.verdict == "clear", (a.verdict, rules(a))


def test_the_span_includes_both_endpoints_even_when_unharvested():
    assert ra.span_versions("7.6.8", "8.0.7", ["8.0.5", "8.0.7"]) == \
        ["7.6.8", "8.0.5", "8.0.7"]


# --------------------------------------------------------------------------- #
#  The seal                                                                     #
# --------------------------------------------------------------------------- #
def test_the_report_names_the_rule_set_that_produced_it():
    a = ra.analyse(FULL, "7.6.9", "8.0.7")
    assert a.rules_digest == ra.rules_digest()
    assert len(a.rules_digest) == 16


def test_the_digest_follows_the_rules_SOURCE_not_just_their_names(monkeypatch):
    """A version string a human bumps is a seal that silently stops sealing.

    The mechanism is driven, not described: ``inspect.getsource`` is made to
    return altered text for the SAME functions, under the SAME names. A first
    version of this guard swapped a rule for a wrapper with a different
    ``__name__`` — and a digest built from names alone passed it, so the guard
    was satisfied by the very mutation it existed to catch."""
    before = ra.rules_digest()
    real = ra.inspect.getsource
    monkeypatch.setattr(ra.inspect, "getsource",
                        lambda fn: real(fn) + "\n# a threshold moved here\n")
    assert ra.rules_digest() != before, \
        "a rule's body changed and the seal did not"


def test_the_digest_also_follows_which_rules_ran():
    """The other half: adding or removing a rule changes the report's seal, so an
    archived advisory cannot claim a rule set it was not produced under."""
    before = ra.rules_digest()
    original = ra.RULES
    try:
        ra.RULES = original[:-1]
        assert ra.rules_digest() != before
    finally:
        ra.RULES = original
    assert ra.rules_digest() == before


def test_every_rule_is_in_the_declared_set():
    """A rule defined and never registered is a verdict nobody gets, and a seal
    that claims to cover it."""
    defined = {n for n in dir(ra) if n.startswith("_rule_")}
    registered = {f.__name__ for f in ra.RULES}
    assert defined == registered, defined ^ registered


def test_every_finding_uses_the_declared_severity_vocabulary():
    for a in (ra.analyse(corpus("7.6.1", "8.0.7"), "7.6.1", "8.0.7"),
              ra.analyse(FULL, "8.0.7", "7.6.9")):
        for f in a.findings:
            assert f.severity in ra.SEVERITIES, (f.rule, f.severity)
