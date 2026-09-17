"""Corroboration — when one source says a thing is GONE, ask a second one.

Why this module exists
----------------------
On 2026-09-17 the firmware comparison reported ``user_group`` as absent on
8.0.5. It was right: the API rejected the URN. But *nothing in the product
could tell that reading apart from a second one that looks identical and is
the opposite* — "the path we hold for that object is wrong on this line". Both
produce the same measured ``absent``, and only the first one is a finding about
the appliance; the second is a finding about **us**.

The answer is not a better badge. It is a rule, written once, that takes a
disappearance claimed by one source and asks a *second, independent* source
whether it agrees — and that reports the four possible outcomes with four
different words, including the two that mean "I cannot tell yet".

This is deliberately product- and transport-agnostic (:func:`corroborate` knows
nothing about REST, CLI or FortiWeb) because the same shape recurs all over
SATOM and every copy of the rule would drift:

* **upgrades** — a capability the running build no longer offers: is it gone,
  or is the probe wrong for this build?
* **provisioning** — a template references an object the target does not have:
  removed upstream, or never provisioned here?
* **templates / clone** — a source object missing on the destination.

Those adopt :func:`corroborate` in a later pass. The one thing that must NOT
happen is a second author for this decision.

The logical lock
----------------
``second_now == ABSENT`` is *by itself* weak evidence: in this product a CLI
dump prints no block for a table the operator never filled in
(``cli_coverage.BUCKET_NO_BLOCK`` says exactly that, and folding it into
"absent" once invented ~96 phantom removals). So absence of a block is not
absence of the object.

What makes the pair conclusive is that the two weaknesses do not overlap:

* an **empty but existing** table still answers ``ok`` over REST — so a
  *rejected URN* excludes the empty-table explanation;
* a *rejected URN* alone cannot distinguish "gone" from "our path is wrong" —
  so the dump, which is addressed by CLI syntax and never by our URN, settles
  that half.

Hence CONFIRMED requires all three: rejected now, no block now, **and a block
before**. Drop any one of them and the verdict drops to UNCORROBORATED, which
is a real answer and not a hedge — it names the capture that would settle it.

Never widened to "the second source is silent, so probably yes". That widening
is how a page earns the right to be ignored.
"""
from __future__ import annotations

# ---- the second source's answer about one name ----------------------------
#: The second source shows the object present.
SRC_PRESENT = "present"
#: The second source was consulted and does not show it.
SRC_ABSENT = "absent"
#: No usable second-source evidence for that scope at all.
SRC_SILENT = "silent"
#: The second source *cannot* carry this object by construction (e.g. a runtime
#: readout has no configuration block). Distinct from SILENT: silence can be
#: fixed by capturing evidence, this cannot, so the two suggest opposite work.
SRC_INAPPLICABLE = "inapplicable"

# ---- the verdict ----------------------------------------------------------
#: Two independent sources agree the object is gone.
STATE_CONFIRMED = "confirmed"
#: The first source says gone, the second says it is right there. The object
#: exists on the box and what we hold for it is wrong. THE actionable one.
STATE_CONTRADICTED = "contradicted"
#: Nothing contradicts it, and nothing corroborates it either.
STATE_UNCORROBORATED = "uncorroborated"
#: No second-source evidence exists for the scope being judged.
STATE_UNMEASURED = "unmeasured"

#: ``state -> (label, css class, what it means, what to do next)``. The
#: vocabulary lives here and not in the templates for the same reason
#: ``cli_coverage.PROV_LABEL`` does: three pages that each spell a verdict
#: cannot be kept in agreement, and this one decides whether somebody edits a
#: catalog.
STATE_LABEL = {
    STATE_CONFIRMED: (
        "gone — corroborated", "fw-badge-danger",
        "two independent sources agree: the build rejects the path, its own "
        "configuration dump has no block for it, and the dump of the build it "
        "is compared against does. An empty table would still answer over "
        "REST, so this is not an unconfigured table.",
        "nothing — this is the finding the comparison exists to produce."),
    STATE_CONTRADICTED: (
        "check the registry", "fw-badge-warning",
        "the build rejects the path, but its own configuration dump DOES hold "
        "a block for this object. The object is on the appliance; the path "
        "this catalog holds is wrong for this firmware line.",
        "verify the path in the console, then correct the catalog entry."),
    STATE_UNCORROBORATED: (
        "gone — one source", "fw-badge-secondary",
        "the build rejects the path and no second source speaks to it: either "
        "the dump never held a block for it on EITHER side, or the object is "
        "a runtime readout that cannot have one.",
        "if it should have a configuration block, capture a dump of the older "
        "build to establish that it ever had one."),
    STATE_UNMEASURED: (
        "not corroborated", "",
        "no configuration dump has been captured for this build, so the "
        "rejection stands on one source alone.",
        "capture a CLI configuration dump of this build."),
}


def corroborate(*, second_now: str, second_before: str) -> str:
    """Judge an absence reported by the FIRST source, using the second.

    The caller has already established that source one reports the object
    absent **on the target scope** and present on the base scope — that is the
    row this function is handed. It answers only the corroboration question, so
    that the "is it a disappearance at all?" logic stays with whoever owns the
    first source.

    ``second_now`` / ``second_before`` are one of the ``SRC_*`` constants.
    """
    if second_now == SRC_PRESENT:
        return STATE_CONTRADICTED
    if second_now == SRC_SILENT:
        return STATE_UNMEASURED
    if second_now == SRC_INAPPLICABLE:
        return STATE_UNCORROBORATED
    # second_now == SRC_ABSENT — conclusive ONLY with a positive "before".
    if second_before == SRC_PRESENT:
        return STATE_CONFIRMED
    return STATE_UNCORROBORATED


def label(state: str) -> tuple:
    """``(text, css, why, next_step)`` — never a KeyError on an unknown state.

    A state this module has never heard of is reported as unmeasured rather
    than crashing a page: a verdict is not worth a 500, and the honest
    fallback is the one that claims least.
    """
    return STATE_LABEL.get(state, STATE_LABEL[STATE_UNMEASURED])


def is_actionable(state: str) -> bool:
    """True for the one state that names work SATOM must do to itself.

    Kept as a function rather than ``state == STATE_CONTRADICTED`` spelled at
    each call site: the alert engine, the page counter and the export all ask
    this question, and the day a fifth state joins, three of them would be
    updated and one would not.
    """
    return state == STATE_CONTRADICTED


# ---------------------------------------------------------------------------
# Adapter: CLI-dump provenance -> the SRC_* vocabulary
# ---------------------------------------------------------------------------
#: ``cli_coverage`` bucket -> second-source answer. Written as data so the
#: mapping can be read (and pinned) rather than inferred from an if-chain.
#:
#: ``BUCKET_NO_BLOCK`` maps to ABSENT and not to SILENT on purpose, and the
#: distinction is the whole reason :func:`corroborate` demands a positive
#: "before": a dump WAS read and it does not mention this object. That is a
#: real datum. It just is not, on its own, a negative one.
_BUCKET_SRC = {
    "both": SRC_PRESENT,
    "near_match": SRC_PRESENT,
    "cli_only": SRC_PRESENT,
    "no_block": SRC_ABSENT,
    "monitor_only": SRC_INAPPLICABLE,
    "unknown": SRC_SILENT,
}


def source_of(prov_rec) -> str:
    """Map one ``Provenance.for_name`` record to a ``SRC_*`` answer.

    ``None`` (the view could not resolve provenance at all) is SILENT, not
    ABSENT — the difference between "we looked and the dump is quiet" and "we
    never looked" is exactly what this module refuses to blur.
    """
    if not prov_rec:
        return SRC_SILENT
    return _BUCKET_SRC.get(prov_rec.get("bucket") or "", SRC_SILENT)


def proposed_path(prov_rec) -> str:
    """The CLI spelling to offer as a correction, or ``""``.

    Only a ``near_match`` yields one: that bucket means both transports carry
    the object and the CLI spells the path differently, so there is a concrete
    alternative to show. ``cli_only`` has a block and no catalog match, and
    ``both`` already agrees — neither implies a new URN.

    This returns the CLI PATH, never a URN. ``cli_coverage`` rule 3 is explicit
    that either spelling could be the wrong one and that a config file cannot
    decide which, so the value travels as evidence for a human, not as a
    ready-to-write catalog value. Anything that turns it into a URN has to say
    so in its own name.
    """
    if not prov_rec:
        return ""
    if (prov_rec.get("bucket") or "") != "near_match":
        return ""
    return prov_rec.get("path") or ""


__all__ = [
    "SRC_PRESENT", "SRC_ABSENT", "SRC_SILENT", "SRC_INAPPLICABLE",
    "STATE_CONFIRMED", "STATE_CONTRADICTED", "STATE_UNCORROBORATED",
    "STATE_UNMEASURED", "STATE_LABEL",
    "corroborate", "label", "is_actionable", "source_of", "proposed_path",
]
